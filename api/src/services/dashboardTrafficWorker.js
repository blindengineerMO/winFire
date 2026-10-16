import {parentPort,workerData} from 'node:worker_threads'
import Database from 'better-sqlite3'
import {refreshProcessExclusions,isExcludedProcess,visibleFirewallEventSql} from '../processExclusions.js'
import {refreshTrafficIgnores,isIgnoredFirewallEvent} from '../trafficIgnores.js'

// This connection never migrates, mutates, or imports the control-plane workers.
const db=new Database(workerData.filename,{readonly:true,fileMustExist:true,timeout:1000})
db.pragma('query_only = ON')
db.function('winfire_excluded_process',value=>Number(isExcludedProcess(value)))
db.function('winfire_ignored_traffic',(eventId,action,protocol,srcIp,dstIp,dstPort,direction,program,accountSid)=>Number(isIgnoredFirewallEvent({eventId,action,protocol,srcIp,dstIp,dstPort,direction,program,accountSid})))
parentPort.on('message',()=>{
  try{
    const result=db.transaction(()=>{
      refreshProcessExclusions(db)
      refreshTrafficIgnores(db)
      const deniedPorts=db.prepare(`SELECT COALESCE(e.dst_port,p.dst_port) dst_port,COUNT(*) count
        FROM log_events e LEFT JOIN event_patterns p ON p.id=e.pattern_id
        WHERE e.action='block' AND ${visibleFirewallEventSql()}
        GROUP BY COALESCE(e.dst_port,p.dst_port) ORDER BY count DESC,dst_port LIMIT 6`).all()
      return {deniedPorts,generatedAt:new Date().toISOString()}
    })()
    parentPort.postMessage({result})
  }catch(error){parentPort.postMessage({error:error.message})}
})
