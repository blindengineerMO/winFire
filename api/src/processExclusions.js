import {ignoredTrafficSql} from './trafficIgnores.js'
const firewallIds=new Set([5150,5151,5156,5157])
let excluded=new Set()

export function processBasename(value){
  const path=String(value??'').trim().replace(/^['"]|['"]$/g,'').replaceAll('/','\\')
  return path.slice(path.lastIndexOf('\\')+1).toLowerCase()
}

// WFP can report a DOS path, a device path, or only the executable name. A
// policy may use either a full path or a basename. Full paths are matched as
// a suffix so a device prefix does not make otherwise identical evidence fail.
export function matchesProcess(value, expression){
  const actual=String(value??'').trim().replace(/^['"]|['"]$/g,'').replaceAll('/','\\').toLowerCase()
  const expected=String(expression??'').trim().replace(/^['"]|['"]$/g,'').replaceAll('/','\\').toLowerCase()
  if(!actual||!expected)return false
  if(expected.includes('\\')){
    const suffix=expected.replace(/^[a-z]:\\/,'').replace(/^\\+/,'')
    return actual===expected||actual.endsWith(`\\${suffix}`)
  }
  return processBasename(actual)===expected
}

export function normalizeProcessExclusions(values){
  if(!Array.isArray(values)||values.length>200)throw new Error('Provide at most 200 executable names')
  const names=values.map(value=>String(value).trim().toLowerCase())
  if(names.some(name=>name.length<5||name.length>255||!name.endsWith('.exe')||/[\\/\x00-\x1f*?"<>|:]/.test(name)))throw new Error('Use executable file names such as openmonx-agent.exe, without a path or wildcard')
  return [...new Set(names)].sort()
}

export function refreshProcessExclusions(db){
  excluded=new Set(db.prepare('SELECT name FROM process_exclusions').all().map(row=>row.name))
  return [...excluded].sort()
}

export function isExcludedFirewallEvent(event){
  if(event?.eventType!=='firewall'&&!firewallIds.has(Number(event?.eventId??event?.event_id)))return false
  return excluded.has(processBasename(event?.program))
}

export function isExcludedProcess(value){return excluded.has(processBasename(value))}

export function visibleFirewallEventSql(eventAlias='e',patternAlias='p'){
  const program=patternAlias?`COALESCE(${eventAlias}.program,${patternAlias}.program)`:`${eventAlias}.program`
  const eventType=patternAlias?`COALESCE(${eventAlias}.event_type,${patternAlias}.event_type)`:`${eventAlias}.event_type`
  return `NOT ((${eventAlias}.event_id IN (5150,5151,5156,5157) OR COALESCE(${eventType},'')='firewall') AND winfire_excluded_process(${program})) AND ${ignoredTrafficSql(eventAlias,patternAlias)}`
}
