const MAX_QUEUE=1000
const FLUSH_SIZE=100
const ALARM='winfire-internet-flush'

async function getState(){
  const state=await chrome.storage.local.get({serverUrl:'',deviceToken:'',deviceId:'',collectionLevel:'host',queue:[],policyVersion:0,policyFailMode:'open'})
  return state
}

async function setQueue(queue){await chrome.storage.local.set({queue:queue.slice(-MAX_QUEUE)})}

function browserName(){
  const ua=self.navigator?.userAgent||''
  return /Edg\//i.test(ua)?'edge':'chrome'
}

async function enqueue(details){
  if(details.frameId!==0||!/^https?:\/\//i.test(details.url)||details.incognito)return
  const state=await getState()
  if(!state.deviceToken||!state.serverUrl)return
  const queue=state.queue||[]
  queue.push({id:crypto.randomUUID(),url:details.url,observedAt:new Date().toISOString(),action:'observed',tabSession:String(details.tabId)})
  await setQueue(queue)
  if(queue.length>=FLUSH_SIZE)await flush()
}

async function flush(){
  const state=await getState()
  if(!state.deviceToken||!state.serverUrl||(state.queue||[]).length===0)return
  const batch=(state.queue||[]).slice(0,FLUSH_SIZE)
  try{
    const response=await fetch(`${state.serverUrl.replace(/\/$/,'')}/api/v1/internet/events:batch`,{method:'POST',headers:{'Content-Type':'application/json',Authorization:`Bearer ${state.deviceToken}`},body:JSON.stringify({events:batch})})
    if(response.status===401||response.status===403){await chrome.storage.local.set({deviceToken:'',deviceId:'',queue:[]});return}
    if(!response.ok)throw new Error(`WinFIRE returned ${response.status}`)
    const ids=new Set(batch.map(item=>item.id))
    await setQueue((state.queue||[]).filter(item=>!ids.has(item.id)))
  }catch(error){console.debug('WinFIRE Internet telemetry queued for retry',error.message)}
}

async function clearPolicy(){
  if(!chrome.declarativeNetRequest?.updateDynamicRules)return
  const existing=await chrome.declarativeNetRequest.getDynamicRules()
  if(existing.length)await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:existing.map(rule=>rule.id)})
}

async function applyOfflineFallback(state){
  if(state.policyFailMode!=='closed'||!chrome.declarativeNetRequest?.updateDynamicRules)return
  const existing=await chrome.declarativeNetRequest.getDynamicRules()
  // A closed policy deliberately blocks top-level web navigation while the
  // control plane is unavailable. A successful sync replaces these rules.
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds:existing.map(rule=>rule.id),
    addRules:[
      {id:2147483001,priority:1,action:{type:'block'},condition:{urlFilter:'|http://',resourceTypes:['main_frame','sub_frame']}},
      {id:2147483002,priority:1,action:{type:'block'},condition:{urlFilter:'|https://',resourceTypes:['main_frame','sub_frame']}}
    ]
  })
}

async function syncPolicy(){
  const state=await getState()
  if(!state.deviceToken||!state.serverUrl)return
  try{
    const response=await fetch(`${state.serverUrl.replace(/\/$/,'')}/api/v1/internet/config`,{headers:{Authorization:`Bearer ${state.deviceToken}`}})
    if(response.status===401||response.status===403){await clearPolicy();await chrome.storage.local.set({deviceToken:'',deviceId:'',queue:[]});return}
    if(!response.ok)throw new Error(`WinFIRE policy returned ${response.status}`)
    const data=await response.json()
    if(!Number.isInteger(data.version)||!Array.isArray(data.rules)||data.rules.length>5000)throw new Error('Invalid WinFIRE policy payload')
    const rules=data.rules.filter(rule=>Number.isInteger(rule.id)&&rule.id>0&&rule.id<=5000&&rule.action?.type&&rule.condition?.urlFilter)
    const existing=await chrome.declarativeNetRequest.getDynamicRules()
    await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:existing.map(rule=>rule.id),addRules:rules})
    await chrome.storage.local.set({policyVersion:data.version,policyFailMode:data.failMode||'open',policySignature:data.signature||''})
  }catch(error){
    await applyOfflineFallback(state).catch(fallbackError=>console.debug('WinFIRE Internet closed-mode fallback unavailable',fallbackError.message))
    console.debug('WinFIRE Internet policy queued for retry',error.message)
  }
}

chrome.runtime.onInstalled.addListener(async()=>{
  const state=await getState()
  if(!state.installId)await chrome.storage.local.set({installId:crypto.randomUUID()})
  chrome.alarms.create(ALARM,{periodInMinutes:1})
  await syncPolicy()
})
chrome.alarms.onAlarm.addListener(alarm=>{if(alarm.name===ALARM){flush();syncPolicy()}})
chrome.webNavigation.onCommitted.addListener(enqueue)
chrome.runtime.onMessage.addListener((message,_sender,sendResponse)=>{
  if(message?.type==='flush'){flush().then(()=>sendResponse({ok:true}));return true}
  if(message?.type==='syncPolicy'){syncPolicy().then(()=>sendResponse({ok:true}));return true}
  if(message?.type==='browser')sendResponse({browser:browserName()})
})
