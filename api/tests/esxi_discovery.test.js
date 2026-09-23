import test from 'node:test'
import assert from 'node:assert/strict'
import {parseEsxiVersion,__private} from '../src/esxiDiscovery.js'

test('ESXi SOAP about information is normalized into a display version',()=>{
  const about='<returnval><name>VMware ESXi</name><fullName>VMware ESXi 8.0.2 build-22380479</fullName><version>8.0.2</version><build>22380479</build></returnval>'
  assert.deepEqual(parseEsxiVersion(about),{name:'VMware ESXi',fullName:'VMware ESXi 8.0.2 build-22380479',version:'8.0.2',build:'22380479',display:'VMware ESXi 8.0.2 build-22380479'})
})

test('ESXi detection helpers recognize SOAP responses and escape credentials',()=>{
  assert.equal(__private.hasVmwareMarker('<soap:Envelope xmlns:vim="urn:vim25"><vim:RetrieveServiceContent/></soap:Envelope>'),true)
  assert.equal(__private.escapeXml("root&'admin"),'root&amp;&apos;admin')
})
