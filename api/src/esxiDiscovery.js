import https from 'node:https'

const DEFAULT_TIMEOUT_MS=2500
const SOAP_NS='http://schemas.xmlsoap.org/soap/envelope/'
const VIM_NS='urn:vim25'

const escapeXml=value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;')

function request(host,{method='GET',body='',headers={},timeoutMs=DEFAULT_TIMEOUT_MS}={}){
  return new Promise((resolve,reject)=>{
    const req=https.request({hostname:host,port:443,path:'/sdk',method,headers:{'User-Agent':'WinFire discovery','Accept':'text/xml, */*',...(body?{'Content-Type':'text/xml; charset=utf-8','Content-Length':Buffer.byteLength(body)}:{}),...headers},rejectUnauthorized:false,timeout:timeoutMs},res=>{
      const chunks=[]
      res.on('data',chunk=>chunks.push(chunk))
      res.on('end',()=>resolve({status:res.statusCode||0,headers:res.headers,body:Buffer.concat(chunks).toString('utf8')}))
    })
    req.on('timeout',()=>req.destroy(Object.assign(new Error('ESXi SOAP request timed out'),{code:'ETIMEDOUT'})))
    req.on('error',reject)
    if(body)req.write(body)
    req.end()
  })
}

const soapEnvelope=body=>`<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="${SOAP_NS}" xmlns:vim="${VIM_NS}"><soapenv:Body>${body}</soapenv:Body></soapenv:Envelope>`
const soapFault=xml=>/<(?:[\w-]+:)?Fault\b/i.test(String(xml||'' ) )
const firstTag=(xml,name)=>String(xml||'').match(new RegExp(`<(?:[\\w-]+:)?${name}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${name}>`,'i'))?.[1]?.replace(/<[^>]+>/g,'').trim()||null
const hasVmwareMarker=xml=>/vmware|esxi|vim25|serviceinstance/i.test(String(xml||''))

export function parseEsxiVersion(xml){
  const source=String(xml||''),fullName=firstTag(source,'fullName'),version=firstTag(source,'version'),build=firstTag(source,'build'),name=firstTag(source,'name')
  const detail=[version,build&&`build ${build}`].filter(Boolean).join(' ')
  return {name:name||'VMware ESXi',fullName:fullName||null,version:version||null,build:build||null,display:fullName||detail||name||'VMware ESXi'}
}

async function retrieveProperties(host,sessionId,collector){
  const body=soapEnvelope(`<vim:RetrieveProperties><vim:_this type="PropertyCollector">${collector||'propertyCollector'}</vim:_this><vim:specSet><vim:propSet><vim:type>ServiceInstance</vim:type><vim:all>false</vim:all><vim:pathSet>content.about</vim:pathSet></vim:propSet><vim:objectSet><vim:obj type="ServiceInstance">ServiceInstance</vim:obj><vim:skip>false</vim:skip></vim:objectSet></vim:specSet></vim:RetrieveProperties>`)
  const headers={SOAPAction:'"RetrieveProperties"'}
  if(sessionId)headers.Cookie=`vmware_soap_session=${sessionId}`
  return request(host,{method:'POST',body,headers})
}

export async function identifyEsxi(host,{credentials=[],timeoutMs=DEFAULT_TIMEOUT_MS}={}){
  const base={detected:false,authenticated:false,host,osName:'VMware ESXi',hypervisor:'VMware ESXi',deviceType:'hypervisor',manageability:'unmanaged',api:'soap'}
  let probe
  try{probe=await request(host,{timeoutMs})}catch(error){return {...base,error:error.message}}
  let marker=probe.status===401||hasVmwareMarker(probe.body)||/text\/xml/i.test(String(probe.headers?.['content-type']||''))
  // ESXi often answers an unauthenticated GET with a generic 405 page. A
  // SOAP RetrieveServiceContent probe gives us a reliable identity signal in
  // that case without requiring a credential.
  if(!marker){
    try{
      const soapProbe=await request(host,{method:'POST',body:soapEnvelope('<vim:RetrieveServiceContent><vim:_this type="ServiceInstance">ServiceInstance</vim:_this></vim:RetrieveServiceContent>'),timeoutMs,headers:{SOAPAction:'"RetrieveServiceContent"'}})
      marker=soapProbe.status===401||hasVmwareMarker(soapProbe.body)||soapFault(soapProbe.body)||/text\/xml/i.test(String(soapProbe.headers?.['content-type']||''))
      if(marker)probe=soapProbe
    }catch{}
  }
  if(!marker)return base
  const detected={...base,detected:true,probeStatus:probe.status}
  for(const credential of Array.isArray(credentials)?credentials:[]){
    if(!credential?.username||!credential?.password)continue
    try{
      const content=soapEnvelope('<vim:RetrieveServiceContent><vim:_this type="ServiceInstance">ServiceInstance</vim:_this></vim:RetrieveServiceContent>')
      const contentResponse=await request(host,{method:'POST',body:content,timeoutMs,headers:{SOAPAction:'"RetrieveServiceContent"'}})
      if(contentResponse.status<200||contentResponse.status>=300||soapFault(contentResponse.body))continue
      const sessionManager=firstTag(contentResponse.body,'sessionManager')||'ha-sessionmgr'
      const collector=firstTag(contentResponse.body,'propertyCollector')||'ha-property-collector'
      const login=soapEnvelope(`<vim:Login><vim:_this type="SessionManager">${sessionManager}</vim:_this><vim:userName>${escapeXml(credential.username)}</vim:userName><vim:password>${escapeXml(credential.password)}</vim:password></vim:Login>`)
      const loginResponse=await request(host,{method:'POST',body:login,timeoutMs,headers:{SOAPAction:'"Login"'}})
      if(loginResponse.status<200||loginResponse.status>=300||soapFault(loginResponse.body))continue
      const cookie=String(Array.isArray(loginResponse.headers?.['set-cookie'])?loginResponse.headers['set-cookie'].join(';'):loginResponse.headers?.['set-cookie']||'').match(/vmware_soap_session=([^;]+)/i)?.[1]||''
      const properties=await retrieveProperties(host,cookie,collector)
      const about=parseEsxiVersion(properties.body||loginResponse.body)
      return {...detected,authenticated:true,credentialUsername:credential.username,osVersion:about.display,version:about.version,build:about.build,fullName:about.fullName}
    }catch{}
  }
  return detected
}

export const __private={escapeXml,firstTag,hasVmwareMarker}
