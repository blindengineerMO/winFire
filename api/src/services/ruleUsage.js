import {z} from 'zod'
import {all,one} from '../db.js'
import {canReadResource} from '../access.js'
import {collectionCoverage} from './collectionCoverage.js'
import {ruleMatch} from './policySimulation.js'

export function ruleUsage(policyId,input,user){
  const p=one('SELECT * FROM policies WHERE id=?',policyId)
  if(!p||!canReadResource(user,'policy',p))throw Object.assign(new Error('Policy not found'),{status:404})
  const q=z.object({from:z.string().datetime({offset:true}).default(new Date(Date.now()-86400000).toISOString()),to:z.string().datetime({offset:true}).default(new Date().toISOString())}).strict().parse(input)
  const start=Date.parse(q.from),end=Date.parse(q.to)
  if(end<=start||end-start>30*86400000||end>Date.now()+60000)throw Object.assign(new Error('Choose a past evidence window of at most 30 days'),{status:400})
  const from=new Date(start).toISOString(),to=new Date(end).toISOString()
  const version=one('SELECT * FROM policy_versions WHERE id=?',p.current_version_id)
  const rules=JSON.parse(version?.rules_compiled_json||'[]')
  if(rules.length>1000)throw Object.assign(new Error('Policy exceeds the 1,000-rule assessment budget'),{status:413})
  const nodes=all('SELECT DISTINCT n.* FROM nodes n JOIN policy_assignments a ON a.node_id=n.id OR a.node_group_id IN (SELECT group_id FROM node_group_members WHERE node_id=n.id) WHERE a.policy_id=? ORDER BY n.id LIMIT 101',policyId)
  if(nodes.length>100)throw Object.assign(new Error('Narrow the policy target set to at most 100 assets for usage assessment'),{status:413})
  const items=rules.map(r=>({ruleId:r.sourceNodeId,name:r.name,matchingObservations:0,indeterminateObservations:0,evidenceEventIds:[],protected:!!(r.localUserSid||r.schedule)})),coverage=[]
  let processed=0,truncated=false
  for(const node of nodes){
    const current=collectionCoverage(node.id,from,to),applied=one('SELECT version_id,status FROM policy_apply_runs WHERE node_id=? AND policy_id=? AND julianday(finished_at)<=julianday(?) ORDER BY julianday(finished_at) DESC,rowid DESC LIMIT 1',node.id,policyId,from)
    const platformSupported=['winrm','winrms','wmi','netsh'].includes(node.transport)||/windows/i.test(node.platform||node.os_name||'')
    coverage.push({nodeId:node.id,hostname:node.hostname,...current,platformSupported,versionConfirmedAtWindowStart:applied?.status==='success'&&applied.version_id===version?.id})
    const limit=Math.min(2500,Math.min(10000,Math.floor(250000/Math.max(1,rules.length)))-processed)
    if(limit<=0){truncated=true;continue}
    const events=all(`SELECT e.*,COALESCE(e.protocol,p.protocol) protocol,COALESCE(e.src_ip,p.src_ip) src_ip,COALESCE(e.dst_ip,p.dst_ip) dst_ip,COALESCE(e.dst_port,p.dst_port) dst_port,COALESCE(e.direction,p.direction) direction,COALESCE(e.program,p.program) program
      FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id WHERE e.node_id=?
      AND COALESCE(julianday(COALESCE(e.event_time,e.received_at)),0)>=julianday(?) AND COALESCE(julianday(COALESCE(e.event_time,e.received_at)),0)<=julianday(?)
      AND e.event_id IN (5150,5151,5156,5157) AND NOT EXISTS(SELECT 1 FROM traffic_observations o WHERE o.event_id=e.id)
      ORDER BY COALESCE(julianday(COALESCE(e.event_time,e.received_at)),0),e.id LIMIT ?`,node.id,from,to,limit+1)
    if(events.length>limit)truncated=true
    for(const event of events.slice(0,limit))for(const [index,rule] of rules.entries()){
      const match=platformSupported?ruleMatch(rule,event).match:null
      if(match===true){items[index].matchingObservations++;if(items[index].evidenceEventIds.length<5)items[index].evidenceEventIds.push(event.id)}else if(match===null)items[index].indeterminateObservations++
    }
    processed+=Math.min(events.length,limit)
  }
  const adequatelyReported=coverage.length>0&&coverage.every(c=>c.coveredMs===c.requestedMs&&c.gaps===0&&!c.truncated&&c.platformSupported&&c.versionConfirmedAtWindowStart)&&!truncated
  for(const item of items)item.assessment=item.matchingObservations?'observed-match':adequatelyReported&&!item.indeterminateObservations?'no-observed-match':'insufficient-evidence'
  return {policyId,versionId:version?.id||null,from,to,items,coverage,processedObservations:processed,truncated,unusedConclusion:'not-established',automaticallyRemoved:false,limitations:['Matching traffic is potential rule use, not proof that this rule permitted or blocked it','Healthy collection windows do not prove lossless telemetry or application coverage','Rule retirement requires reviewed simulation and verified deployment; foreign and identity rules remain protected']}
}
