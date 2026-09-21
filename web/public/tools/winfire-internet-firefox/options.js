const form=document.querySelector('#form'),status=document.querySelector('#status'),submit=document.querySelector('#submit')
const setStatus=(text,kind='')=>{status.textContent=text;status.className=`status ${kind}`}
async function load(){
  const state=await chrome.storage.local.get({serverUrl:'',deviceId:''})
  if(state.serverUrl)document.querySelector('#serverUrl').value=state.serverUrl
  if(state.deviceId)setStatus(`Enrolled as device ${state.deviceId}.`,'success')
}
form.addEventListener('submit',async event=>{
  event.preventDefault();submit.disabled=true;setStatus('Requesting browser access…')
  try{
    const granted=await chrome.permissions.request({origins:['*://*/*']})
    if(!granted)throw new Error('Host access is required for Internet visibility')
    const serverUrl=document.querySelector('#serverUrl').value.trim().replace(/\/$/,'')
    const token=document.querySelector('#token').value.trim()
    const {installId}=await chrome.storage.local.get({installId:crypto.randomUUID()})
    await chrome.storage.local.set({installId,serverUrl})
    const browser=(await chrome.runtime.sendMessage({type:'browser'}))?.browser||'chrome'
    const response=await fetch(`${serverUrl}/api/v1/internet/enroll`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,browser,extensionVersion:chrome.runtime.getManifest().version,installId,capabilities:{webNavigation:true,privateBrowsing:false}})})
    const data=await response.json().catch(()=>({}))
    if(!response.ok)throw new Error(data.error||'Enrollment failed')
    await chrome.storage.local.set({serverUrl,deviceToken:data.deviceToken,deviceId:data.deviceId,collectionLevel:data.collectionLevel,queue:[]})
    await chrome.runtime.sendMessage({type:'syncPolicy'})
    document.querySelector('#token').value='';setStatus(`Enrolled successfully. Device ${data.deviceId} is reporting host metadata.`,'success')
  }catch(error){setStatus(error.message,'error')}
  finally{submit.disabled=false}
})
load()
