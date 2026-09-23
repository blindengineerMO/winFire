import {Client} from 'ssh2'
import {Buffer} from 'node:buffer'

const COMMAND_TIMEOUT=20_000
const MAX_OUTPUT=512*1024

function fingerprint(value){
  return String(value||'').trim().replace(/^sha256:/i,'')
}
function hostKeyMatches(expected,actual){
  if(!expected)return true
  const want=fingerprint(expected),got=fingerprint(actual)
  if(want===got||want.toLowerCase().replace(/:/g,'')===got.toLowerCase().replace(/:/g,''))return true
  try{return want.replace(/=+$/,'')===Buffer.from(got,'hex').toString('base64').replace(/=+$/,'')}catch{return false}
}
export function sshHostKeyPolicy(credential={}){
  const expected=credential.hostKeyFingerprint||credential.hostKey||credential.thumbprint||''
  return expected?{mode:'verify',fingerprint:expected}:{mode:'accept-any',fingerprint:null}
}

export function sshExec({host,port=22,username,password,privateKey,passphrase,hostKeyFingerprint,hostKey,command,timeout=COMMAND_TIMEOUT,connectFactory=()=>new Client()}={}){
  if(!host)throw new Error('SSH host is required')
  if(!username)throw new Error('SSH username is required')
  if(!command)throw new Error('SSH command is required')
  return new Promise((resolve,reject)=>{
    const client=connectFactory(); let settled=false,stdout='',stderr=''
    const finish=(error,result)=>{if(settled)return;settled=true;clearTimeout(timer);try{client.end()}catch{};error?reject(error):resolve(result)}
    const timer=setTimeout(()=>finish(new Error('SSH command timed out')),timeout)
    client.once('error',error=>finish(error))
    client.once('ready',()=>{
      client.exec(command,{env:{LANG:'C',LC_ALL:'C'}},(error,stream)=>{
        if(error)return finish(error)
        stream.on('data',chunk=>{stdout+=chunk.toString();if(stdout.length>MAX_OUTPUT)finish(new Error('SSH command output exceeded the safety limit'))})
        stream.stderr.on('data',chunk=>{stderr+=chunk.toString();if(stderr.length>MAX_OUTPUT)finish(new Error('SSH command error output exceeded the safety limit'))})
        stream.once('close',(code,signal)=>finish(null,{code:Number(code||0),signal:signal||null,stdout,stderr}))
      })
    })
    const config={host,port:Number(port)||22,username,readyTimeout:Math.min(timeout,15_000),hostHash:'sha256',hostVerifier:key=>hostKeyMatches(hostKeyFingerprint||hostKey,key)}
    if(privateKey)config.privateKey=privateKey
    else if(password)config.password=password
    client.connect(config)
  })
}

async function commandResult(connection,command){
  try{return await sshExec({...connection,command})}catch(error){return {code:-1,stdout:'',stderr:error.message,error}}
}
export function parseLinuxOsRelease(text){
  const values={}
  for(const line of String(text||'').split(/\r?\n/)){const match=line.match(/^([A-Z_]+)=(.*)$/);if(!match)continue;values[match[1]]=match[2].replace(/^"|"$/g,'')}
  return values
}
function parseJson(text){try{return JSON.parse(String(text||''))}catch{return null}}
function prettyOs(os,uname){
  const name=os.PRETTY_NAME||os.NAME||'Linux / Unix'
  const version=os.VERSION_ID||os.VERSION||String(uname||'').trim()||null
  return {Caption:name,Version:version,BuildNumber:String(uname||'').trim()||null}
}
export function parseIptablesRules(text){
  return String(text||'').split(/\r?\n/).filter(line=>line.startsWith('-A ')).map((line,index)=>{
    const token=(key)=>{const match=line.match(new RegExp(`(?:^| )${key} (?:"([^"]+)"|(\\S+))`));return match?.[1]??match?.[2]??null}
    const chain=line.split(/\s+/)[1]||'INPUT'
    const target=String(token('-j')||'ACCEPT').toUpperCase()
    return {name:`iptables-${index+1}`,raw:line,action:['DROP','REJECT'].includes(target)?'block':'allow',direction:chain==='INPUT'?'in':chain==='OUTPUT'?'out':'forward',protocol:token('-p')||'any',localPort:token('--dport')||token('--dports')||'Any',remoteAddress:token('-s')||'Any'}
  })
}
export function parseUfwRules(text){
  return String(text||'').split(/\r?\n/).filter(line=>/^(?:\d+|\d+\/\w+|[\w-]+)\s+(?:ALLOW|DENY|REJECT|LIMIT)\b/i.test(line.trim())).map((line,index)=>({name:`ufw-${index+1}`,raw:line,action:/\bDENY\b|\bREJECT\b/i.test(line)?'block':'allow',direction:/\bIN\b/i.test(line)?'in':/\bOUT\b/i.test(line)?'out':'in',service:line.trim()}))
}
function normalizeNeighbors(value){
  return Array.isArray(value)?value.map(item=>({ip:item.dst||item.address||item.ip||null,mac:item.lladdr||item.mac||null,state:item.state||item.reachability||null,interface:item.dev||item.interface||null})).filter(item=>item.ip):[]
}
function parseSsConnections(text){
  return String(text||'').split(/\r?\n/).map(line=>line.trim()).filter(line=>line&&!/^state\s+/i.test(line)).map(line=>{
    const parts=line.split(/\s+/),state=parts[0],local=parts[4]||parts[3]||'',remote=parts[5]||parts[4]||''
    const endpoint=value=>{const match=String(value).match(/^(.*):([0-9]+)$/);return match?{address:match[1].replace(/^\[|\]$/g,''),port:Number(match[2])||null}:{address:value||null,port:null}}
    return {state,local:endpoint(local),remote:endpoint(remote),process:parts.slice(6).join(' ')||null,raw:line}
  }).filter(item=>item.local.address||item.remote.address)
}

export async function collectLinuxFacts(connection){
  const commands={uname:'uname -srmo',osRelease:'cat /etc/os-release 2>/dev/null',hostname:'hostname -f 2>/dev/null || hostname',addresses:'ip -j addr 2>/dev/null',neighbors:'ip -j neigh 2>/dev/null',routes:'ip -j route 2>/dev/null',connections:'ss -Htanup 2>/dev/null',iptables:'sudo -n iptables-save 2>/dev/null || iptables-save 2>/dev/null',nft:'sudo -n nft -j list ruleset 2>/dev/null || nft -j list ruleset 2>/dev/null',ufw:'sudo -n ufw status verbose 2>/dev/null || ufw status verbose 2>/dev/null',firewalld:'sudo -n systemctl is-active firewalld 2>/dev/null || systemctl is-active firewalld 2>/dev/null'}
  const result={};for(const [key,command] of Object.entries(commands))result[key]=await commandResult(connection,command)
  const os=parseLinuxOsRelease(result.osRelease.stdout),uname=result.uname.stdout.trim(),hostname=result.hostname.stdout.trim()||connection.host
  const addresses=parseJson(result.addresses.stdout)||[],neighbors=parseJson(result.neighbors.stdout)||[],routes=parseJson(result.routes.stdout)||[],connections=parseJson(result.connections.stdout)||parseSsConnections(result.connections.stdout)
  const ufwActive=/^status:\s+(active|inactive)/im.exec(result.ufw.stdout)?.[1]==='active',firewalldActive=/^active$/im.test(result.firewalld.stdout),nftRules=parseJson(result.nft.stdout)
  const firewall=ufwActive?{backend:'ufw',rules:parseUfwRules(result.ufw.stdout),status:'active'}:nftRules?{backend:'nftables',rules:Array.isArray(nftRules?.nftables)?nftRules.nftables:[],status:'active'}:{backend:firewalldActive?'firewalld':'iptables',rules:parseIptablesRules(result.iptables.stdout),status:firewalldActive?'active':'unknown'}
  const network=addresses.flatMap(item=>Array.isArray(item.addr_info)?item.addr_info.map(addr=>({name:item.ifname,macAddress:item.address,ipAddress:addr.local,prefixLength:addr.prefixlen})):[])
  return {success:true,transport:'ssh',computerName:hostname,computer:{Name:hostname},os:prettyOs(os,uname),network,arp:normalizeNeighbors(neighbors),routes,connections,firewall,service:{Name:firewall.backend,Status:firewall.status},linux:{osRelease:os,uname},raw:{neighbors:result.neighbors.stdout,routes:result.routes.stdout,connections:result.connections.stdout}}
}
export async function collectLinuxRules(connection){
  const facts=await collectLinuxFacts(connection)
  return {rules:facts.firewall?.rules||[],total:(facts.firewall?.rules||[]).length,backend:facts.firewall?.backend||'iptables',status:facts.firewall?.status||'unknown'}
}
function safeValue(value,pattern){const text=String(value||'').trim();return text&&pattern.test(text)?text:null}
export async function applyLinuxFirewall(connection,args={}){
  const ufw=await commandResult(connection,'ufw status 2>/dev/null')
  const isUfw=/^status:\s+active/im.test(ufw.stdout),commands=[]
  const normalizeRule=rule=>{const action=String(rule.action||'allow').toLowerCase()==='block'||String(rule.action||'').toLowerCase()==='deny'?'deny':'allow',protocol=safeValue(rule.protocol,/^(tcp|udp|icmp|any)$/i)||'tcp',port=safeValue(rule.port||rule.localPort,/^\d{1,5}(-\d{1,5})?$/)||null,source=safeValue(rule.source||rule.remoteAddress,/^(any|\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)$/i)||'any';if(!port&&protocol!=='icmp')throw new Error('A valid destination port is required for Linux firewall changes');return {action,protocol,port,source}}
  const commandFor=(rule,remove=false)=>{const value=normalizeRule(rule),verb=remove?'delete ':'';if(isUfw)return `ufw ${verb}${value.action} ${value.port||value.protocol}${value.source!=='any'?` from ${value.source}`:''}`;const target=value.action==='allow'?'ACCEPT':'DROP',parts=['iptables',remove?'-D':'-A','INPUT'];if(value.protocol!=='any')parts.push('-p',value.protocol);if(value.port)parts.push('--dport',value.port);if(value.source!=='any')parts.push('-s',value.source);parts.push('-j',target);return parts.join(' ')}
  for(const rule of Array.isArray(args.add)?args.add:[args])commands.push(commandFor(rule,false))
  for(const rule of Array.isArray(args.remove)?args.remove:[])commands.push(commandFor(rule,true))
  if(!commands.length)throw new Error('No Linux firewall changes were supplied')
  for(const command of commands){const result=await commandResult(connection,`sudo -n ${command}`);if(result.code!==0)throw new Error(result.stderr||`Linux firewall command failed (${result.code})`)}
  return {applied:true,backend:isUfw?'ufw':'iptables',commands:commands.map(command=>command.replace(/\s+/g,' ').trim())}
}
export async function testSshCredential({host,credential,port=22,probeOnly=false}={}){
  const secret=credential?.secret||credential||{},result=await sshExec({host,port:credential?.port||port,username:credential?.username||secret.username,password:secret.password,privateKey:secret.privateKey,passphrase:secret.passphrase,hostKeyFingerprint:secret.hostKeyFingerprint||secret.hostKey,command:probeOnly?'printf SSH_AUTHENTICATED':'hostname -f 2>/dev/null || hostname',timeout:15_000})
  if(result.code!==0)throw new Error(result.stderr||'SSH authentication failed')
  return {success:true,transport:'ssh',account:credential?.username||secret.username,computerName:result.stdout.trim()||null}
}

function shellQuote(value){
  return `'${String(value??'').replace(/'/g,"'\\''")}'`
}

function parseLoginctlProperties(text){
  const properties={}
  for(const line of String(text||'').split(/[|\r\n]/)){
    const index=line.indexOf('=')
    if(index<1)continue
    properties[line.slice(0,index)]=line.slice(index+1)
  }
  return properties
}

export function parseLinuxGuiSessions(text,preferredUser=null){
  const wanted=String(preferredUser||'').trim().toLowerCase()
  return String(text||'').split(/\r?\n/).map(line=>{
    const properties=parseLoginctlProperties(line)
    return {id:properties.Id||properties.ID||null,user:properties.Name||properties.User||null,uid:properties.User||null,type:String(properties.Type||'').toLowerCase(),class:String(properties.Class||'').toLowerCase(),state:String(properties.State||'').toLowerCase(),remote:String(properties.Remote||'').toLowerCase(),display:properties.Display||null,leader:properties.Leader||null,home:properties.Home||null,runtimePath:properties.RuntimePath||null,waylandDisplay:properties.WaylandDisplay||null}
  }).filter(session=>session.id&&session.user&&(!wanted||session.user.toLowerCase()===wanted)&&['x11','wayland'].includes(session.type)&&['active','online'].includes(session.state)&&!['yes','true','1'].includes(session.remote)&&session.class==='user'&&session.user!=='root')
}

async function findLinuxGuiSession(connection,preferredUser=null){
  const sessions=await commandResult(connection,"loginctl list-sessions --no-legend 2>/dev/null | while read -r id rest; do loginctl show-session \"$id\" -p Id -p Name -p User -p Type -p Class -p State -p Remote -p Display -p Leader 2>/dev/null | paste -sd '|' -; done")
  const candidates=parseLinuxGuiSessions(sessions.stdout,preferredUser)
  if(!candidates.length)throw new Error('No active local X11 or Wayland session was found')
  const selected=candidates[0]
  const identity=await commandResult(connection,`getent passwd ${shellQuote(selected.user)} 2>/dev/null | awk -F: '{print $3"|"$6}'`)
  const [uid,home]=String(identity.stdout||'').trim().split('|')
  if(!/^\d+$/.test(uid)||!home)throw new Error(`Could not resolve the home directory for ${selected.user}`)
  selected.uid=uid;selected.home=home;selected.runtimePath=`/run/user/${uid}`
  if(selected.type==='wayland'){
    const runtime=await commandResult(connection,`loginctl show-user ${shellQuote(selected.user)} -p RuntimePath --value 2>/dev/null`)
    if(runtime.code===0&&runtime.stdout.trim())selected.runtimePath=runtime.stdout.trim()
    const wayland=await commandResult(connection,`find ${shellQuote(selected.runtimePath)} -maxdepth 1 -type s -name 'wayland-*' -printf '%f\\n' 2>/dev/null | head -n 1`)
    selected.waylandDisplay=wayland.stdout.trim()||'wayland-0'
  }
  return selected
}

function portalUrl(value){
  let url
  try{url=new URL(String(value||''))}catch{throw new Error('A valid MFA portal URL is required')}
  if(!['https:','http:'].includes(url.protocol)||url.username||url.password||url.hash)throw new Error('MFA portal URL must be an HTTP(S) URL without credentials or fragments')
  return url.href
}

function launchCommand(session,url,browser='xdg-open'){
  const executable=/^[A-Za-z0-9._+/-]+$/.test(String(browser))?String(browser):'xdg-open'
  const target=shellQuote(url)
  const runAs=(command)=>`if [ "$(id -un)" = ${shellQuote(session.user)} ]; then ${command}; else sudo -n -u ${shellQuote(session.user)} -- ${command}; fi`
  if(session.type==='x11'){
    const env=`env DISPLAY=${shellQuote(session.display||':0')} XAUTHORITY=${shellQuote(`${session.home}/.Xauthority`)} ${executable} ${target}`
    return runAs(`nohup ${env} >/dev/null 2>&1 </dev/null & echo $!`)
  }
  const systemd=`systemd-run --machine=${shellQuote(`${session.user}@.host`)} --user --quiet ${executable} ${target}`
  const fallback=`env XDG_RUNTIME_DIR=${shellQuote(session.runtimePath)} WAYLAND_DISPLAY=${shellQuote(session.waylandDisplay||'wayland-0')} ${executable} ${target}`
  return `${systemd} || ${runAs(`nohup ${fallback} >/dev/null 2>&1 </dev/null & echo $!`)}`
}

export async function launchLinuxPortal(connection,{portalUrl:requestedUrl,preferredUser=null,browser='xdg-open'}={}){
  const url=portalUrl(requestedUrl),session=await findLinuxGuiSession(connection,preferredUser)
  const result=await commandResult(connection,launchCommand(session,url,browser))
  if(result.code!==0)throw new Error(result.stderr.trim()||'The MFA portal could not be opened in the Linux desktop session')
  const processId=String(result.stdout||'').trim().split(/\s+/).pop()||null
  return {opened:true,transport:'ssh',user:session.user,sessionId:session.id,processId,desktop:session.type,display:session.display||session.waylandDisplay||null,portalUrl:url}
}
