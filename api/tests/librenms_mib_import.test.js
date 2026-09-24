import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {createHash} from 'node:crypto'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-librenms-test-'))
process.env.DATA_DIR=path.join(dir,'data')
process.env.SNMP_MIB_LIBRARY_DIR=path.join(dir,'sources')
const {db}=await import('../src/db.js')
const {importMibs,updateMib}=await import('../src/snmpMibLibrary.js')
const {sourcePath}=await import('../src/snmpMibStorage.js')
const {importLibreNmsCatalog}=await import('../../scripts/import-librenms-mibs.mjs')
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})

test('recursive catalog import preserves working definitions, source folders and local dependency variants',async()=>{
  const repo=path.join(dir,'librenms'),revision='a'.repeat(40)
  const fixture=name=>fs.readFileSync(new URL('./fixtures/mibs/'+name,import.meta.url),'utf8')
  const smi=fixture('WINFIRE-TEST-SMI.mib'),mib=fixture('WINFIRE-TEST-MIB.mib')
  await importMibs({files:[{filename:'WINFIRE-TEST-SMI.mib',content:smi},{filename:'WINFIRE-TEST-MIB.mib',content:mib}]},null)
  const prior=db.prepare("SELECT * FROM snmp_mib_library WHERE module_name='WINFIRE-TEST-MIB'").get()
  updateMib(prior.id,{enabled:false,selectedObjects:['modelName'],match:{sysDescrContains:['Custom device'],sysObjectIdPrefixes:[]}},null)
  const original=db.prepare('SELECT * FROM snmp_mib_library WHERE id=?').get(prior.id)
  const inputs=new Map([
    ['vendor-a/SMI',smi.replace('424242','424241')],
    ['vendor-b/SMI',smi.replace('424242','424243')],
    ['SMI',smi.replace('424242','424244')],
    ['vendor-b/DEVICE-MIB',mib.replaceAll('WINFIRE-TEST-MIB','NEW-DEVICE-MIB').replace('DEFINITIONS','-- Header comment\nDEFINITIONS')],
    ['vendor-a/EXISTING-MIB',mib.replace('Device model','Changed source description')],
    ['broken/BROKEN-MIB','BROKEN-MIB DEFINITIONS ::= BEGIN\nIMPORTS nope FROM ABSENT-MIB;\nEND'],
    ['broken/INVALID','INVALID-MIB DEFINITIONS ::= BEGIN\n"unterminated'],
    ['core/SNMPv2-SMI','SNMPv2-SMI DEFINITIONS ::= BEGIN\nEND']
  ])
  for(const [filename,content] of inputs){const dest=path.join(repo,'mibs',filename);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.writeFileSync(dest,content)}
  fs.symlinkSync(path.join(repo,'mibs'),path.join(repo,'mibs','cycle'))
  const report=await importLibreNmsCatalog({repo,revision,log:()=>{}})
  assert.equal(report.sourceFiles,inputs.size)
  assert.equal(report.ready,1)
  assert.equal(report.retainedExisting,2)
  assert.equal(report.bundled,1)
  assert.equal(report.errors.length,2)
  assert.deepEqual(db.prepare('SELECT * FROM snmp_mib_library WHERE id=?').get(prior.id),original)
  const imported=db.prepare("SELECT * FROM snmp_mib_library WHERE module_name='NEW-DEVICE-MIB'").get()
  assert.equal(imported.enabled,0)
  assert.equal(imported.filename,'mibs/vendor-b/DEVICE-MIB')
  const metadata=JSON.parse(imported.metadata_json)
  assert.equal(metadata.objects.find(o=>o.name==='modelName').oid,'1.3.6.1.4.1.424243.1.1.0')
  assert.equal(metadata.sourceDependencies.find(d=>d.module==='WINFIRE-TEST-SMI').filename,'mibs/vendor-b/SMI')
  assert.equal(JSON.parse(imported.config_json).selectedObjects.length,3)
  const sources=db.prepare("SELECT * FROM snmp_mib_files WHERE origin='librenms/librenms'").all()
  for(const row of sources){
    const expected=Buffer.from(inputs.get(row.filename.slice(5)))
    assert.deepEqual(fs.readFileSync(sourcePath(row.source_path)),expected)
    assert.equal(row.sha256,createHash('sha256').update(expected).digest('hex'))
    assert.equal(row.revision,revision)
    assert.ok(row.source_url.endsWith('/'+row.filename))
  }
  const count=db.prepare('SELECT count(*) n FROM snmp_mib_library').get().n
  const rerun=await importLibreNmsCatalog({repo,revision,log:()=>{}})
  assert.equal(rerun.ready,0)
  assert.equal(rerun.retainedExisting,3)
  assert.equal(db.prepare('SELECT count(*) n FROM snmp_mib_library').get().n,count)
  assert.equal(db.prepare("SELECT count(*) n FROM snmp_mib_files WHERE origin='librenms/librenms'").get().n,inputs.size)
  assert.equal(db.prepare("SELECT status FROM snmp_mib_files WHERE filename='mibs/vendor-b/DEVICE-MIB'").get().status,'ready')
  assert.deepEqual(db.prepare('SELECT * FROM snmp_mib_library WHERE id=?').get(prior.id),original)
})
