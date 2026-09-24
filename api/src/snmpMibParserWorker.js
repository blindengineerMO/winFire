import {parentPort,workerData} from 'node:worker_threads'
import snmp from 'net-snmp'
import {mibEnvelope} from './snmpMibSyntax.js'

// The dependency's ASN.1 parser runs off the API thread with memory/time limits.
// ParseModule accepts text directly: filenames, imports and descriptions never run code.
try {
  const store=snmp.createModuleStore(),baseNames=store.getModuleNames(true)
  const files=workerData.files,byName=new Map(),ordered=[],visiting=new Set(),done=new Set()
  for(const file of files){
    const cleaned=mibEnvelope(file.content)
    const headers=[...cleaned.matchAll(/([A-Za-z][\w-]*)\s+DEFINITIONS\s*::=\s*BEGIN/g)]
    if(headers.length!==1||! /\bEND\s*$/.test(cleaned.trim()))throw Error(`${file.filename}: expected one complete ASN.1 MIB module (DEFINITIONS ::= BEGIN … END)`)
    const moduleName=headers[0][1]
    if(baseNames.includes(moduleName))throw Error(`${moduleName} is a bundled SMI dependency and cannot be replaced`)
    if(byName.has(moduleName))throw Error(`Duplicate module ${moduleName} in import`)
    const imports=[...(cleaned.match(/\bIMPORTS\b([\s\S]*?);/)?.[1]||'').matchAll(/\bFROM\s+([A-Za-z][\w-]*)/g)].map(m=>m[1])
    byName.set(moduleName,{...file,moduleName,imports})
  }
  function visit(name){
    if(done.has(name)||baseNames.includes(name))return
    if(visiting.has(name))throw Error(`Circular MIB dependency involving ${name}`)
    const file=byName.get(name)
    if(!file)throw Error(`Missing dependency ${name}. Import it together with the MIB that needs it.`)
    visiting.add(name);file.imports.forEach(visit);visiting.delete(name);done.add(name);ordered.push(file)
  }
  byName.forEach((_,name)=>visit(name))
  // Avoid emitting untrusted module text into server logs.
  console.log=()=>{};console.warn=()=>{}
  for(const file of ordered)store.parser.ParseModule(file.moduleName,file.content)
  store.parser.Serialize()
  const result=[]
  for(const file of ordered){
    const module=store.getModule(file.moduleName)
    if(!module)throw Error(`${file.moduleName}: module could not be parsed`)
    for(const [dependency,names] of Object.entries(module.IMPORTS||{})){
      for(const name of names){if(!store.getModule(dependency)?.[name])throw Error(`${file.moduleName}: unresolved import ${name} FROM ${dependency}`)}
    }
    const entries=Object.values(module).filter(e=>e&&typeof e==='object'&&e.ObjectName)
    const oidEntries=entries.filter(e=>e['OBJECT IDENTIFIER'])
    const invalid=oidEntries.find(e=>!/^\d+(?:\.\d+)+$/.test(e.OID||''))
    if(invalid)throw Error(`${file.moduleName}: cannot resolve OID for ${invalid.ObjectName}`)
    if(entries.length>10000)throw Error(`${file.moduleName}: too many definitions (maximum 10000)`)
    const rows=entries.filter(e=>e.INDEX||e.AUGMENTS).map(e=>e.OID)
    const objects=entries.filter(e=>e.MACRO==='OBJECT-TYPE'&&['read-only','read-write','read-create'].includes(e['MAX-ACCESS']||e.ACCESS)&&/^\d+(?:\.\d+)+$/.test(e.OID||'')).map(e=>{
      const kind=rows.some(root=>e.OID.startsWith(root+'.'))?'column':'scalar'
      return {name:e.ObjectName,oid:e.OID+(kind==='scalar'?'.0':''),kind,syntax:typeof e.SYNTAX==='string'?e.SYNTAX:JSON.stringify(e.SYNTAX),units:e.UNITS||null,description:String(e.DESCRIPTION||'').slice(0,1000)}
    })
    const prefixes=[...new Set(oidEntries.map(e=>e.OID.match(/^(1\.3\.6\.1\.4\.1\.\d+)(?:\.|$)/)?.[1]).filter(Boolean))]
    result.push({moduleName:file.moduleName,imports:file.imports,objects,definitionCount:entries.length,description:String(entries.find(e=>e.MACRO==='MODULE-IDENTITY')?.DESCRIPTION||'Imported MIB').slice(0,1000),match:{sysObjectIdPrefixes:prefixes,sysDescrContains:[]}})
  }
  parentPort.postMessage({modules:result})
}catch(error){parentPort.postMessage({error:String(error.message||'Unable to parse MIB').slice(0,1000)})}
