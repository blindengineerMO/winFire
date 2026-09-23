import test from 'node:test'
import assert from 'node:assert/strict'
import {parseEsxiVersion,parseVirtualMachineInventory,identifyEsxi,__private} from '../src/esxiDiscovery.js'

test('ESXi SOAP about information is normalized into a display version',()=>{
  const about='<returnval><name>VMware ESXi</name><fullName>VMware ESXi 8.0.2 build-22380479</fullName><version>8.0.2</version><build>22380479</build></returnval>'
  assert.deepEqual(parseEsxiVersion(about),{name:'VMware ESXi',fullName:'VMware ESXi 8.0.2 build-22380479',version:'8.0.2',build:'22380479',display:'VMware ESXi 8.0.2 build-22380479'})
})

test('ESXi detection helpers recognize SOAP responses and escape credentials',()=>{
  assert.equal(__private.hasVmwareMarker('<soap:Envelope xmlns:vim="urn:vim25"><vim:RetrieveServiceContent/></soap:Envelope>'),true)
  assert.equal(__private.escapeXml("root&'admin"),'root&amp;&apos;admin')
})

test('ESXi guest property sets are normalized for inventory correlation',()=>{
  const xml='<returnval><obj type="VirtualMachine">vm-42</obj><propSet><name>name</name><val>web-01</val></propSet><propSet><name>config.uuid</name><val>uuid-42</val></propSet><propSet><name>guest.ipAddress</name><val>192.168.88.42</val></propSet><propSet><name>guest.hostName</name><val>web-01.example.test</val></propSet><propSet><name>summary.config.guestFullName</name><val>Ubuntu Linux (64-bit)</val></propSet><propSet><name>runtime.powerState</name><val>poweredOn</val></propSet><propSet><name>summary.config.numCpu</name><val>4</val></propSet><propSet><name>summary.config.memorySizeMB</name><val>8192</val></propSet></returnval>'
  assert.deepEqual(parseVirtualMachineInventory(xml),[{
    name:'web-01',uuid:'uuid-42',ip:'192.168.88.42',hostname:'web-01.example.test',guestOs:'Ubuntu Linux (64-bit)',powerState:'poweredOn',cpuCount:4,memoryMb:8192
  }])
})

test('ESXi SOAP authentication keeps the session cookie and retrieves host and guest inventory',async()=>{
  const serviceContent='<returnval><rootFolder type="Folder">ha-folder-root</rootFolder><propertyCollector type="PropertyCollector">ha-property-collector</propertyCollector><viewManager type="ViewManager">ViewManager</viewManager><about><name>VMware ESXi</name><fullName>VMware ESXi 8.0.3 build-24677879</fullName><version>8.0.3</version><build>24677879</build></about><sessionManager type="SessionManager">ha-sessionmgr</sessionManager></returnval>'
  const vm='<returnval><obj type="VirtualMachine">vm-42</obj><propSet><name>name</name><val>web-01</val></propSet><propSet><name>guest.ipAddress</name><val>192.168.88.42</val></propSet><propSet><name>runtime.powerState</name><val>poweredOn</val></propSet></returnval>'
  const responses=[
    {status:404,headers:{},body:''},
    {status:200,headers:{'set-cookie':['vmware_soap_session="initial"; Path=/']},body:`<RetrieveServiceContentResponse xmlns="urn:vim25">${serviceContent}</RetrieveServiceContentResponse>`},
    {status:200,headers:{'set-cookie':['vmware_soap_session="initial-2"; Path=/']},body:`<RetrieveServiceContentResponse xmlns="urn:vim25">${serviceContent}</RetrieveServiceContentResponse>`},
    {status:200,headers:{'set-cookie':['vmware_soap_session="session-42"; Path=/']},body:'<LoginResponse xmlns="urn:vim25"><returnval/></LoginResponse>'},
    {status:200,headers:{},body:`<RetrievePropertiesResponse xmlns="urn:vim25">${serviceContent}</RetrievePropertiesResponse>`},
    {status:200,headers:{},body:'<CreateContainerViewResponse xmlns="urn:vim25"><returnval>view-42</returnval></CreateContainerViewResponse>'},
    {status:200,headers:{},body:`<RetrievePropertiesResponse xmlns="urn:vim25">${vm}</RetrievePropertiesResponse>`},
    {status:200,headers:{},body:'<DestroyViewResponse xmlns="urn:vim25"/>'}
  ]
  const calls=[]
  const result=await identifyEsxi('esxi.test',{timeoutMs:100,credentials:[{username:'root',password:'secret'}],requestFn:async(_host,options)=>{calls.push(options);return responses.shift()}})
  assert.equal(result.detected,true)
  assert.equal(result.authenticated,true)
  assert.equal(result.osVersion,'VMware ESXi 8.0.3 build-24677879')
  assert.deepEqual(result.virtualMachines,[{name:'web-01',uuid:null,ip:'192.168.88.42',hostname:null,guestOs:null,powerState:'poweredOn',cpuCount:null,memoryMb:null}])
  assert.match(calls[3].headers.Cookie,/vmware_soap_session=initial-2/)
  assert.match(calls[4].headers.Cookie,/vmware_soap_session=session-42/)
})
