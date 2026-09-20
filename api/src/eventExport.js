import tls from 'node:tls'
import {isIP} from 'node:net'

export function validateExportDestination(kind,endpoint){
  const invalid=message=>{throw Object.assign(new Error(message),{status:400})}
  if(kind==='splunk_hec'){
    let url
    try{url=new URL(endpoint)}catch{invalid('Splunk HEC endpoint must be a valid HTTPS URL')}
    if(url.protocol!=='https:'||url.username||url.password||url.hash||!url.hostname)invalid('Splunk HEC endpoint must be an HTTPS URL without credentials or a fragment')
    if(!url.pathname.endsWith('/services/collector/event'))invalid('Splunk HEC endpoint must end in /services/collector/event')
    return url.toString()
  }
  if(kind==='syslog_tls'){
    const match=String(endpoint).match(/^([^\s:/?#]+):(\d{1,5})$/)
    if(!match||Number(match[2])<1||Number(match[2])>65535)invalid('Syslog TLS endpoint must be a hostname and port, such as logs.example.com:6514')
    return `${match[1]}:${Number(match[2])}`
  }
  invalid('Unsupported export destination type')
}

export function syslogFrame(event){
  const timestamp=new Date(event.event_time||event.received_at||Date.now()).toISOString()
  const payload=JSON.stringify({product:'WinFire',...event})
  const message=`<134>1 ${timestamp} winfire WinFire - FIREWALL_EVENT - ${payload}`
  return `${Buffer.byteLength(message)} ${message}`
}

export async function exportSelectedEvents(destination,events,token,{fetchImpl=fetch,tlsConnect=tls.connect}={}){
  if(!events.length)throw new Error('Select at least one event')
  if(destination.kind==='splunk_hec'){
    const body=events.map(event=>JSON.stringify({time:Math.floor(new Date(event.event_time||event.received_at).getTime()/1000),host:event.hostname||event.node_id||'winfire',source:'winfire',sourcetype:'winfire:security',event})).join('\n')
    const response=await fetchImpl(destination.endpoint,{method:'POST',headers:{Authorization:`Splunk ${token}`,'Content-Type':'application/json'},body,redirect:'error',signal:AbortSignal.timeout(30000)})
    const reply=await response.json().catch(()=>null)
    if(!response.ok||reply?.code!==0)throw new Error(`Splunk HEC rejected the export (${response.status}${reply?.code===undefined?'':`, code ${reply.code}`})`)
    return {sent:events.length,kind:'splunk_hec'}
  }
  if(destination.kind==='syslog_tls'){
    const endpoint=validateExportDestination(destination.kind,destination.endpoint),separator=endpoint.lastIndexOf(':'),host=endpoint.slice(0,separator),port=Number(endpoint.slice(separator+1))
    await new Promise((resolve,reject)=>{
      const socket=tlsConnect({host,port,...(!isIP(host)?{servername:host}:{}),rejectUnauthorized:true,timeout:30000})
      let settled=false
      const fail=error=>{if(settled)return;settled=true;socket.destroy();reject(error)}
      socket.once('error',fail);socket.once('timeout',()=>fail(new Error('Syslog TLS connection timed out')))
      socket.once('secureConnect',()=>{
        if(!socket.authorized)return fail(new Error('Syslog TLS certificate was not validated'))
        socket.end(events.map(syslogFrame).join(''),error=>{if(error)return fail(error);if(!settled){settled=true;resolve()}})
      })
    })
    return {sent:events.length,kind:'syslog_tls'}
  }
  throw new Error('Unsupported export destination type')
}
