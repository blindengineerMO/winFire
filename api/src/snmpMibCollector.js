import snmp from 'net-snmp'
import {builtinMibProfiles} from './snmpMibCatalog.js'
const encodeVarbind=vb=>({oid:vb.oid,type:vb.type,value:vb.type===snmp.ObjectType.Counter64&&Buffer.isBuffer(vb.value)?BigInt('0x'+(vb.value.toString('hex')||'0')).toString():snmpValue(vb.value),...(Buffer.isBuffer(vb.value)?{hex:vb.value.subarray(0,256).toString('hex')}:{})})

export function snmpValue(value){
  if(Buffer.isBuffer(value)||value instanceof Uint8Array){
    const bytes=Buffer.from(value),text=bytes.toString('utf8')
    return /^[\x09\x0a\x0d\x20-\x7e]*$/.test(text)?text.slice(0,1024):bytes.subarray(0,256).toString('hex')
  }
  if(typeof value==='bigint')return value.toString()
  return typeof value==='string'?value.slice(0,1024):value??null
}
export function boundedWalk(session,oid,{maxValues=2048,timeoutMs=6000,maxRepetitions=25}={}){
  return new Promise(resolve=>{
    const values=[],seen=new Set();let ended=false,truncated=false
    const finish=(status,error=null)=>{if(ended)return;ended=true;clearTimeout(timer);resolve({status:values.length&&status==='unsupported'?'ok':status,values,truncated,error})}
    const timer=setTimeout(()=>finish('timeout','Query exceeded its time limit'),timeoutMs)
    if(typeof session.subtree!=='function'){finish('unsupported');return}
    try{session.subtree(oid,maxRepetitions,varbinds=>{
      if(ended)return true
      for(const vb of varbinds){
        if(snmp.isVarbindError(vb)||!vb.oid?.startsWith(oid+'.')||seen.has(vb.oid))continue
        seen.add(vb.oid);values.push(encodeVarbind(vb))
        if(values.length>=maxValues){truncated=true;finish('partial');return true}
      }
      return false
    },error=>finish(error?'error':values.length?'ok':'unsupported',error?'SNMP subtree unavailable':null))}catch{finish('error','SNMP subtree unavailable')}
  })
}
function boundedGet(session,oid,timeoutMs){
  return new Promise(resolve=>{
    let ended=false
    const finish=result=>{if(ended)return;ended=true;clearTimeout(timer);resolve(result)}
    const timer=setTimeout(()=>finish({status:'timeout',values:[],error:'Query exceeded its time limit'}),timeoutMs)
    try{session.get([oid],(error,values)=>{
      const vb=values?.[0]
      finish(error?{status:'error',values:[],error:'SNMP object unavailable'}:!vb||snmp.isVarbindError(vb)||vb.value===null||vb.value===undefined?{status:'unsupported',values:[]}:{status:'ok',values:[encodeVarbind({...vb,oid})]})
    })}catch{finish({status:'error',values:[],error:'SNMP object unavailable'})}
  })
}
export async function collectMibPlan(session,plan,{deadline=Date.now()+30000,maxQueries=128,maxValues=8192}={}){
  let consumed=0,reserved=0,queries=0,index=0
  const result={identityKey:plan.identityKey,profiles:plan.profiles.map(p=>({...p,objects:[],status:'unsupported'}))}
  const tasks=plan.profiles.flatMap((p,i)=>p.objects.map(object=>({object,profile:result.profiles[i]})))
  const cache=new Map()
  async function worker(){
    while(index<tasks.length){
      const {object,profile}=tasks[index++],key=object.kind+':'+object.oid
      let response
      if(cache.has(key))response=await cache.get(key)
      else if(Date.now()>=deadline||queries>=maxQueries||consumed+reserved>=maxValues)response={status:'skipped',values:[],error:'Per-device collection budget reached'}
      else{
        queries++
        const allowance=object.kind==='scalar'?1:Math.min(1024,maxValues-consumed-reserved)
        reserved+=allowance
        const promise=object.kind==='scalar'?boundedGet(session,object.oid,Math.min(5000,deadline-Date.now())):boundedWalk(session,object.oid,{maxValues:allowance,timeoutMs:Math.min(5000,deadline-Date.now())})
        cache.set(key,promise);response=await promise;reserved-=allowance;consumed+=response.values.length
      }
      profile.objects.push({name:object.name,oid:object.oid,kind:object.kind,units:object.units||null,...response})
    }
  }
  await Promise.all(Array.from({length:4},worker))
  for(const p of result.profiles){
    const good=p.objects.some(o=>o.values.length),partial=p.objects.some(o=>['error','timeout','skipped','partial'].includes(o.status))
    p.status=good?(partial?'partial':'supported'):p.objects.some(o=>o.status==='timeout')?'timeout':p.objects.some(o=>o.status==='error')?'error':p.objects.some(o=>o.status==='skipped')?'skipped':'unsupported'
  }
  result.queryCount=queries;result.valueCount=consumed;result.truncated=result.profiles.some(p=>['partial','skipped'].includes(p.status));return result
}
// Convert numeric column instances into the legacy row shape used by mapping.
export function walkTable(result,root){
  const rows={}
  for(const {oid,value,hex} of result.values||[]){
    if(!oid.startsWith(root+'.1.'))continue
    const [column,...index]=oid.slice(root.length+3).split('.')
    if(!index.length)continue
    const key=index.join('.');rows[key]??={};const macColumn=({'1.3.6.1.2.1.4.22':'2','1.3.6.1.2.1.4.35':'4','1.3.6.1.2.1.2.2':'6','1.3.6.1.2.1.17.4.3':'1','1.3.6.1.2.1.17.7.1.2.2':'1'})[root];rows[key][column]=hex&&column===macColumn?hex:value
  }
  return rows
}
export function collectionObject(collection,name){return collection.profiles.flatMap(p=>p.objects).find(o=>o.name===name)}
export function collectionTable(collection,name){const o=collectionObject(collection,name);if(o)return walkTable(o,o.oid);const root=builtinMibProfiles.flatMap(p=>p.objects).find(o=>o.name===name)?.oid;return root?walkTable({values:collection.profiles.flatMap(p=>p.objects.flatMap(o=>o.values))},root):{}}
export function normalizedHardware(collection){return Object.entries(collectionTable(collection,'entPhysicalTable')).map(([index,c])=>({index,description:c[2]||null,containedIn:c[4]??null,class:c[5]??null,name:c[7]||null,hardwareRevision:c[8]||null,firmwareRevision:c[9]||null,softwareRevision:c[10]||null,serialNumber:c[11]||null,manufacturer:c[12]||null,model:c[13]||null}))}
