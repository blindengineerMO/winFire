import {all} from '../db.js'
import {isLocalAssetNode} from './networkBoundary.js'

const assignments=`SELECT node_id,policy_id FROM policy_assignments WHERE node_id IS NOT NULL
  UNION SELECT m.node_id,a.policy_id FROM policy_assignments a JOIN node_group_members m ON m.group_id=a.node_group_id`

export function driftSummaryByNode(){
  // Seek once per assigned node/policy, rather than once per historical check.
  const latest=all(`WITH assigned AS (${assignments})
    SELECT a.node_id,(SELECT d.status FROM policy_drift_checks d
      WHERE d.node_id=a.node_id AND d.policy_id=a.policy_id AND d.version_id=p.current_version_id
      ORDER BY datetime(d.checked_at) DESC,d.rowid DESC LIMIT 1) status
    FROM assigned a LEFT JOIN policies p ON p.id=a.policy_id`)
  const byNode=new Map()
  const rank={'in-sync':0,unchecked:1,pending:2,unknown:3,drift:4}
  for(const row of latest){
    const status=row.status||'unchecked',previous=byNode.get(row.node_id)
    if(previous===undefined||(rank[status]??0)>(rank[previous]??0))byNode.set(row.node_id,status)
  }
  return byNode
}

export function reportCoverage(){
  const drift=driftSummaryByNode()
  return all(`WITH assigned AS (${assignments}), counts AS (
      SELECT node_id,COUNT(*) policy_count FROM assigned GROUP BY node_id
    ) SELECT n.id,n.hostname,n.ip,n.scope_id,n.status,COALESCE(c.policy_count,0) policy_count,
      (SELECT status FROM policy_apply_runs WHERE node_id=n.id AND policy_id IS NOT NULL ORDER BY started_at DESC LIMIT 1) last_apply_status,
      (SELECT passed FROM verifier_results WHERE node_id=n.id ORDER BY run_at DESC LIMIT 1) last_verify_passed
    FROM nodes n LEFT JOIN counts c ON c.node_id=n.id ORDER BY n.hostname`)
    .filter(isLocalAssetNode).map(row=>({...row,drift_status:drift.get(row.id)||null}))
}
