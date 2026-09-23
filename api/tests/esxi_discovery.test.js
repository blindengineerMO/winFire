import test from 'node:test'
import assert from 'node:assert/strict'
import {parseEsxiVersion,parseVirtualMachineInventory,__private} from '../src/esxiDiscovery.js'

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
