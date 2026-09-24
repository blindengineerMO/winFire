import http from 'node:http'
import https from 'node:https'
import net from 'node:net'

const REQUEST_TIMEOUT_MS=700
const MAX_RESPONSE_BYTES=128*1024
const bounded=value=>String(value??'').trim().slice(0,256)||null
const fingerprintEvidence=(matched,signal,method='https-fingerprint',confidence='high')=>({source:'infrastructure-discovery',method,matched,signal:bounded(signal),confidence})

/**
 * Classify a small HTTP/HTTPS response without relying on DNS or credentials.
 * These fingerprints are deliberately conservative: a port being open alone
 * is not enough to label a host as a hypervisor.
 */
export function classifyInfrastructureResponse({port,headers={},body=''}={}){
  const headerText=Object.entries(headers||{}).map(([key,value])=>`${key}:${value}`).join(' ')
  const haystack=`${headerText}\n${body}`.toLowerCase()
  if(/vmware\s*(?:esxi|vsphere)|esxi\s*(?:web|host|server)/i.test(haystack))return {vendor:'VMware ESXi',hypervisor:'VMware ESXi',hypervisorName:'VMware ESXi',osName:'VMware ESXi',manageability:'unmanaged',snmpCapable:1,evidence:`https/${port}`,classificationEvidence:fingerprintEvidence('VMware ESXi',`https/${port}`)}
  if(/proxmox\s*(?:virtual environment|ve)|pve\s*(?:manager|proxy)/i.test(haystack))return {vendor:'Proxmox VE',hypervisor:'Proxmox VE',hypervisorName:'Proxmox VE',osName:'Proxmox VE',manageability:'unmanaged',snmpCapable:1,evidence:`https/${port}`,classificationEvidence:fingerprintEvidence('Proxmox VE',`https/${port}`)}
  if(/(?:citrix\s+hypervisor|xenserver|xcp-ng|xcpng)/i.test(haystack))return {vendor:'Citrix Hypervisor / XenServer',hypervisor:'XenServer',hypervisorName:'Citrix Hypervisor / XenServer',osName:'Citrix Hypervisor / XenServer',manageability:'unmanaged',snmpCapable:1,evidence:`https/${port}`,classificationEvidence:fingerprintEvidence('Citrix Hypervisor / XenServer',`https/${port}`)}
  if(/(?:azure\s+local|azure\s+stack\s+hci)/i.test(haystack))return {vendor:'Azure Local',hypervisor:'Azure Local',hypervisorName:'Azure Local',osName:'Azure Local',manageability:'unmanaged',snmpCapable:1,evidence:`https/${port}`,classificationEvidence:fingerprintEvidence('Azure Local',`https/${port}`)}
  return null
}

export function classifyOperatingSystem({caption,version,build}={}){
  const raw=String(caption||'').trim().replace(/^microsoft\s+/i,'')
  const versionText=String(version||'').trim()
  const buildNumber=Number.parseInt(String(build||versionText.split('.')[2]||''),10)
  const windowsRelease=buildNumber>=26100?'24H2':buildNumber>=22631?'23H2':buildNumber>=22621?'22H2':buildNumber>=22000?'21H2':buildNumber===19045?'22H2':buildNumber===19044?'21H2':buildNumber===19043?'21H1':buildNumber===19042?'20H2':buildNumber===19041?'2004':null
  if(raw){
    if(windowsRelease&&/windows\s+(?:10|11)\b/i.test(raw)&&!/(?:20H2|21H[12]|22H2|23H2|24H2|2004)\b/i.test(raw))return `${raw} · ${windowsRelease}`
    return raw
  }
  if(/^10\.0\./.test(versionText)){
    if(buildNumber>=22000)return `Windows 11 ${windowsRelease||''}`.trim()
    if(buildNumber>=19041)return `Windows 10${windowsRelease?` ${windowsRelease}`:''}`
    return 'Windows'
  }
  return versionText||null
}

export function classifyInfrastructureFacts(facts={}){
  const values=[facts?.os?.Caption,facts?.computer?.Model,facts?.computer?.Manufacturer,facts?.computer?.Domain].filter(Boolean).join(' ')
  const result=classifyInfrastructureResponse({body:values})
  if(result)return {...result,classificationEvidence:{...result.classificationEvidence,source:'authenticated-facts',method:'host-facts',signal:'OS / computer identity facts'}}
  return null
}

function httpFingerprint(host,port,secure){
  return new Promise(resolve=>{
    const transport=secure?https:http
    const request=transport.get({host,port,path:'/',rejectUnauthorized:false,timeout:REQUEST_TIMEOUT_MS,headers:{'User-Agent':'WinFire-discovery/1.0','Accept':'text/html,text/plain;q=0.8'}},response=>{
      const chunks=[];let size=0
      response.on('data',chunk=>{size+=chunk.length;if(size<=MAX_RESPONSE_BYTES)chunks.push(chunk)})
      response.on('end',()=>resolve({port,headers:response.headers,body:Buffer.concat(chunks).toString('utf8')}))
    })
    request.once('error',()=>resolve(null));request.once('timeout',()=>{request.destroy();resolve(null)})
  })
}

function tcpOpen(host,port){
  return new Promise(resolve=>{
    const socket=net.createConnection({host,port})
    const finish=value=>{try{socket.destroy()}catch{};resolve(value)}
    socket.setTimeout(REQUEST_TIMEOUT_MS)
    socket.once('connect',()=>finish(true));socket.once('timeout',()=>finish(false));socket.once('error',()=>finish(false))
  })
}

/** Probe only well-known management surfaces; this is not a port scan. */
export async function detectInfrastructureHost(host,{request=httpFingerprint,tcp=tcpOpen}={}){
  const checks=await Promise.all([
    request(host,443,true),
    request(host,8006,true),
    request(host,80,false)
  ])
  for(const response of checks){
    const identified=classifyInfrastructureResponse(response||{})
    if(identified)return identified
  }
  // ESXi can expose its UI only through an appliance gateway while retaining
  // the distinctive vSphere management port.
  if(await tcp(host,902))return {vendor:'VMware ESXi',hypervisor:'VMware ESXi',hypervisorName:'VMware ESXi',osName:'VMware ESXi',manageability:'unmanaged',snmpCapable:1,evidence:'tcp/902',classificationEvidence:fingerprintEvidence('VMware ESXi','tcp/902','tcp-probe','medium')}
  return null
}
