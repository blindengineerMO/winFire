import {db,all,one,run,id} from '../db.js'

// Consecutive authenticated health reports describe a reported collection window.
// They do not prove lossless capture or attribute a flow to a specific firewall rule.
export function recordCollectionHealth(nodeId,source,healthy,{at=new Date()}={}){
  return db.transaction(()=>{
    const stamp=at.toISOString(),last=one('SELECT * FROM collection_coverage_windows WHERE node_id=? AND source=? ORDER BY ended_at DESC LIMIT 1',nodeId,source)
    if(!healthy){if(last)run('UPDATE collection_coverage_windows SET closed=1 WHERE id=?',last.id);return}
    if(last&&!last.closed&&Date.parse(stamp)>=Date.parse(last.ended_at)&&Date.parse(stamp)-Date.parse(last.ended_at)<=90000){run('UPDATE collection_coverage_windows SET ended_at=?,reports=reports+1 WHERE id=?',stamp,last.id);return}
    if(last)run('UPDATE collection_coverage_windows SET closed=1 WHERE id=?',last.id)
    run('INSERT INTO collection_coverage_windows(id,node_id,source,started_at,ended_at,reports) VALUES(?,?,?,?,?,1)',id(),nodeId,source,stamp,stamp)
  })()
}
export function collectionCoverage(nodeId,from,to){
  const rows=all('SELECT started_at,ended_at,reports FROM collection_coverage_windows WHERE node_id=? AND ended_at>=? AND started_at<=? ORDER BY started_at LIMIT 10001',nodeId,from,to)
  const start=Date.parse(from),end=Date.parse(to);let coveredMs=0,last=start,gaps=0
  for(const row of rows.slice(0,10000)){
    if(row.reports<2)continue
    const a=Math.max(start,Date.parse(row.started_at)),b=Math.min(end,Date.parse(row.ended_at))
    if(a>last)gaps++
    if(b>Math.max(a,last))coveredMs+=b-Math.max(a,last)
    last=Math.max(last,b)
  }
  if(last<end)gaps++
  return {coveredMs,requestedMs:end-start,coveragePercent:Number((100*coveredMs/(end-start)).toFixed(2)),gaps,truncated:rows.length>10000,kind:'authenticated-collector-health',losslessCaptureEstablished:false}
}
export function pruneCollectionCoverage(){return run("DELETE FROM collection_coverage_windows WHERE rowid IN (SELECT rowid FROM collection_coverage_windows WHERE ended_at<datetime('now','-90 days') LIMIT 1000)").changes}
