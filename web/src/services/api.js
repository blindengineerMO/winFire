const base='/api/v1'
let sessionGeneration=0,refreshFlight=null
export const session={
  get token(){return localStorage.getItem('winfire_access')},
  get refresh(){return localStorage.getItem('winfire_refresh')},
  setTokens(data){sessionGeneration++;localStorage.setItem('winfire_access',data.accessToken);localStorage.setItem('winfire_refresh',data.refreshToken);localStorage.setItem('winfire_user',JSON.stringify(data.user))},
  clear(){sessionGeneration++;localStorage.removeItem('winfire_access');localStorage.removeItem('winfire_refresh');localStorage.removeItem('winfire_user')},
  get user(){try{return JSON.parse(localStorage.getItem('winfire_user'))}catch{return null}}
}
async function refreshSession(){
  const token=session.refresh,generation=sessionGeneration
  if(!token)return false
  if(refreshFlight?.token===token)return refreshFlight.promise
  const promise=(async()=>{
    const response=await fetch(base+'/auth/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refreshToken:token})})
    if(!response.ok){
      // Network/server failures are retryable; they do not revoke a session.
      if([400,401,403].includes(response.status)&&sessionGeneration===generation){session.clear();location.assign('/login')}
      return false
    }
    const data=await response.json()
    if(sessionGeneration!==generation||session.refresh!==token)return false
    session.setTokens(data)
    return true
  })()
  refreshFlight={token,promise}
  try{return await promise}finally{if(refreshFlight?.promise===promise)refreshFlight=null}
}
export async function api(path,options={},retry=true){
  const accessToken=session.token
  const multipart=options.body instanceof FormData
  const response=await fetch(base+path,{...options,headers:{...(!multipart?{'Content-Type':'application/json'}:{}),...(session.token?{Authorization:`Bearer ${session.token}`}:{}) ,...(options.headers||{})},body:options.body&&!multipart&&typeof options.body!=='string'?JSON.stringify(options.body):options.body})
  if(response.status===401&&retry&&session.refresh){
    if(options.signal?.aborted)throw new DOMException('Request aborted','AbortError')
    // A slower 401 may arrive after another request already rotated the token.
    if(session.token!==accessToken||await refreshSession())return api(path,options,false)
    throw new Error('Unable to refresh session; try again')
  }
  if(!response.ok){
    const data=await response.json().catch(()=>({error:response.statusText}))
    const detail=data.conflicts?.slice(0,3).map(c=>`${c.hostname}: ${c.rule} conflicts with ${c.otherPolicy} / ${c.otherRule}`).join('; ')
    const failure=new Error([data.error||'Request failed',detail].filter(Boolean).join(' — '))
    failure.status=response.status
    failure.onboardingError=data.onboardingError||null
    throw failure
  }
  if(response.status===204)return null
  return response.json()
}
export async function download(path,filename){
  const accessToken=session.token
  let response=await fetch(base+path,{headers:{Authorization:`Bearer ${session.token}`}})
  if(response.status===401&&session.refresh){
    if(session.token!==accessToken||await refreshSession())response=await fetch(base+path,{headers:{Authorization:`Bearer ${session.token}`}})
  }
  if(!response.ok)throw new Error(`Export failed (${response.status})`)
  const url=URL.createObjectURL(await response.blob()),link=document.createElement('a')
  link.href=url;link.download=filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
}
