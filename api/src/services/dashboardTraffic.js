import {Worker} from 'node:worker_threads'
import {createHash} from 'node:crypto'
import {db,all} from '../db.js'

const configured=Number(process.env.DASHBOARD_TRAFFIC_CACHE_SECONDS??10)
const cacheMs=(Number.isFinite(configured)?Math.min(60,Math.max(0,configured)):10)*1000
let worker=null,pending=null,cached=null
const visibilityKey=()=>createHash('sha256').update(JSON.stringify([
  all('SELECT name FROM process_exclusions ORDER BY name'),
  all('SELECT fingerprint FROM traffic_ignore_rules ORDER BY fingerprint')
])).digest('hex')

function readTraffic(key){
  if(pending)return pending
  const current=worker||new Worker(new URL('./dashboardTrafficWorker.js',import.meta.url),{workerData:{filename:db.name}})
  if(!worker){
    current.on('error',()=>{if(worker===current)worker=null})
    current.on('exit',()=>{if(worker===current)worker=null})
  }
  worker=current
  current.ref()
  pending=new Promise((resolve,reject)=>{
    const finish=(error,result)=>{
      clearTimeout(timer)
      current.removeListener('message',onMessage)
      current.removeListener('error',onError)
      current.removeListener('exit',onExit)
      pending=null
      if(error){if(worker===current)worker=null;current.terminate().catch(()=>{});reject(Object.assign(error,{status:503}))}
      else{current.unref();resolve({key,result})}
    }
    const onMessage=message=>finish(message.error?new Error('Dashboard traffic summary is temporarily unavailable'):null,message.result)
    const onError=()=>finish(new Error('Dashboard traffic summary is temporarily unavailable'))
    const onExit=()=>finish(new Error('Dashboard traffic reader stopped'))
    const timer=setTimeout(()=>finish(new Error('Dashboard traffic summary timed out; try again')),30000)
    current.once('message',onMessage)
    current.once('error',onError)
    current.once('exit',onExit)
    current.postMessage({read:true})
  })
  return pending
}

export async function dashboardTraffic(){
  // Visibility changes invalidate immediately, even while a previous read runs.
  // Event ingestion/retention can be reflected up to cacheMs later.
  for(let attempt=0;attempt<3;attempt++){
    const key=visibilityKey()
    if(cached?.key===key&&cached.expires>Date.now())return cached.result
    const read=await readTraffic(key)
    if(read.key!==key||visibilityKey()!==key)continue
    const result=read.result
    cached={key,result,expires:Date.now()+cacheMs}
    return result
  }
  throw Object.assign(new Error('Traffic visibility settings changed; refresh the summary'),{status:409})
}

export async function closeDashboardTraffic(){
  cached=null
  const current=worker
  worker=null
  if(current)await current.terminate()
}
