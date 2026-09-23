import https from 'node:https'

const DEFAULT_TIMEOUT_MS=2500
const SOAP_NS='http://schemas.xmlsoap.org/soap/envelope/'
const VIM_NS='urn:vim25'

const escapeXml=value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;')

export function hypervisorRequest(host,{port=443,path='/',method='GET',body='',headers={},timeoutMs=DEFAULT_TIMEOUT_MS}={}){
  return new Promise((resolve,reject)=>{
    const req=https.request({hostname:host,port,path,method,headers:{'User-Agent':'WinFire discovery','Accept':'text/xml, */*',...(body?{'Content-Type':'text/xml; charset=utf-8','Content-Length':Buffer.byteLength(body)}:{}),...headers},rejectUnauthorized:false,timeout:timeoutMs},res=>{
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

const request=(host,options={})=>hypervisorRequest(host,{path:'/sdk',...options})

const soapEnvelope=body=>`<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="${SOAP_NS}" xmlns:vim="${VIM_NS}"><soapenv:Body>${body}</soapenv:Body></soapenv:Envelope>`
const soapFault=xml=>/<(?:[\w-]+:)?Fault\b/i.test(String(xml||'' ) )
const firstTag=(xml,name)=>String(xml||'').match(new RegExp(`<(?:[\\w-]+:)?${name}\\b[^>]*>([\\s\\S]*?)</(?:[\\w-]+:)?${name}>`,'i'))?.[1]?.replace(/<[^>]+>/g,'').trim()||null
const hasVmwareMarker=xml=>/vmware|esxi|vim25|serviceinstance/i.test(String(xml||''))
const xmlText=value=>String(value||'').replace(/<[^>]+>/g,'').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&amp;/g,'&').trim()

/** Parse the compact property sets returned for VirtualMachine objects. */
export function parseVirtualMachineInventory(xml){
  const source=String(xml||''),machines=[]
  for(const match of source.matchAll(/<(?:[\w-]+:)?returnval\b[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?returnval>/gi)){
    const block=match[1],values={}
    for(const property of block.matchAll(/<(?:[\w-]+:)?propSet\b[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?propSet>/gi)){
      const prop=property[1],name=firstTag(prop,'name'),value=xmlText(firstTag(prop,'val'))
      if(name)values[name]=value||null
    }
    const name=values.name||null
    if(!name)continue
    const memory=Number(values['summary.config.memorySizeMB'])
    const cpu=Number(values['summary.config.numCpu']||values['config.hardware.numCPU'])
    machines.push({
      name,
      uuid:values['config.uuid']||null,
      ip:values['guest.ipAddress']||null,
      hostname:values['guest.hostName']||null,
      guestOs:values['summary.config.guestFullName']||values['summary.config.guestId']||null,
      powerState:values['runtime.powerState']||null,
      cpuCount:Number.isFinite(cpu)&&cpu>0?cpu:null,
      memoryMb:Number.isFinite(memory)&&memory>0?memory:null
    })
  }
  return machines
}

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

async function retrieveVirtualMachines(host,sessionId,{collector='propertyCollector',viewManager='ViewManager',rootFolder='group-d1'}={}){
  const headers={SOAPAction:'"CreateContainerView"',Cookie:`vmware_soap_session=${sessionId}`}
  const create=soapEnvelope(`<vim:CreateContainerView><vim:_this type="ViewManager">${escapeXml(viewManager)}</vim:_this><vim:container type="Folder">${escapeXml(rootFolder)}</vim:container><vim:type>VirtualMachine</vim:type><vim:recursive>true</vim:recursive></vim:CreateContainerView>`)
  const created=await request(host,{method:'POST',body:create,headers})
  if(created.status<200||created.status>=300||soapFault(created.body))return []
  const view=firstTag(created.body,'returnval')
  if(!view)return []
  const body=soapEnvelope(`<vim:RetrieveProperties><vim:_this type="PropertyCollector">${escapeXml(collector)}</vim:_this><vim:specSet><vim:propSet><vim:type>VirtualMachine</vim:type><vim:all>false</vim:all><vim:pathSet>name</vim:pathSet><vim:pathSet>config.uuid</vim:pathSet><vim:pathSet>guest.ipAddress</vim:pathSet><vim:pathSet>guest.hostName</vim:pathSet><vim:pathSet>summary.config.guestFullName</vim:pathSet><vim:pathSet>summary.config.guestId</vim:pathSet><vim:pathSet>summary.config.numCpu</vim:pathSet><vim:pathSet>summary.config.memorySizeMB</vim:pathSet><vim:pathSet>runtime.powerState</vim:pathSet></vim:propSet><vim:objectSet><vim:obj type="ContainerView">${escapeXml(view)}</vim:obj><vim:skip>false</vim:skip><vim:selectSet><vim:name>view</vim:name><vim:type>ContainerView</vim:type><vim:path>view</vim:path><vim:skip>false</vim:skip></vim:selectSet></vim:objectSet></vim:specSet></vim:RetrieveProperties>`)
  const response=await request(host,{method:'POST',body,headers:{SOAPAction:'"RetrieveProperties"',Cookie:`vmware_soap_session=${sessionId}`}})
  try{await request(host,{method:'POST',body:soapEnvelope(`<vim:DestroyView><vim:_this type="ContainerView">${escapeXml(view)}</vim:_this></vim:DestroyView>`),headers:{SOAPAction:'"DestroyView"',Cookie:`vmware_soap_session=${sessionId}`}})}catch{}
  if(response.status<200||response.status>=300||soapFault(response.body))return []
  return parseVirtualMachineInventory(response.body)
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
      const viewManager=firstTag(contentResponse.body,'viewManager')||'ViewManager'
      const rootFolder=firstTag(contentResponse.body,'rootFolder')||'group-d1'
      const login=soapEnvelope(`<vim:Login><vim:_this type="SessionManager">${sessionManager}</vim:_this><vim:userName>${escapeXml(credential.username)}</vim:userName><vim:password>${escapeXml(credential.password)}</vim:password></vim:Login>`)
      const loginResponse=await request(host,{method:'POST',body:login,timeoutMs,headers:{SOAPAction:'"Login"'}})
      if(loginResponse.status<200||loginResponse.status>=300||soapFault(loginResponse.body))continue
      const cookie=String(Array.isArray(loginResponse.headers?.['set-cookie'])?loginResponse.headers['set-cookie'].join(';'):loginResponse.headers?.['set-cookie']||'').match(/vmware_soap_session=([^;]+)/i)?.[1]||''
      const properties=await retrieveProperties(host,cookie,collector)
      const about=parseEsxiVersion(properties.body||loginResponse.body)
      let virtualMachines=[]
      try{virtualMachines=await retrieveVirtualMachines(host,cookie,{collector,viewManager,rootFolder})}catch{}
      return {...detected,authenticated:true,credentialUsername:credential.username,osVersion:about.display,version:about.version,build:about.build,fullName:about.fullName,virtualMachines,virtualMachineCount:virtualMachines.length}
    }catch{}
  }
  return detected
}

/**
 * Identify common infrastructure hypervisors with bounded, unauthenticated
 * HTTPS probes. This runs after liveness and is intentionally independent of
 * WinRM, WMI, SMB, and SNMP so appliance hosts still get a useful identity.
 */
export async function identifyHypervisor(host,{credentials=[],timeoutMs=DEFAULT_TIMEOUT_MS}={}){
  const esxi=await identifyEsxi(host,{credentials,timeoutMs})
  if(esxi.detected)return esxi
  const base={detected:false,authenticated:false,host,deviceType:'hypervisor',manageability:'unmanaged',snmpEligible:true}
  const probes=[
    {kind:'proxmox',port:8006,path:'/api2/json/version',markers:/proxmox|pve-manager|pveversion/i,osName:'Proxmox VE',hypervisor:'Proxmox VE',api:'proxmox-api'},
    {kind:'xenserver',port:443,path:'/',markers:/xenserver|xcp-ng|citrix hypervisor|xen orchestra/i,osName:'Citrix Hypervisor / XenServer',hypervisor:'XenServer',api:'xen-api'},
    {kind:'azure-local',port:443,path:'/',markers:/azure local|azure stack hci|azurestack/i,osName:'Azure Local',hypervisor:'Azure Local',api:'azure-local'}
  ]
  for(const probe of probes){
    try{
      const response=await hypervisorRequest(host,probe)
      if((probe.kind==='proxmox'&&response.status===401)||probe.markers.test(response.body||''))return {...base,...probe,detected:true,probeStatus:response.status}
    }catch{}
  }
  return base
}

export const __private={escapeXml,firstTag,hasVmwareMarker,hypervisorRequest,retrieveVirtualMachines,xmlText}
