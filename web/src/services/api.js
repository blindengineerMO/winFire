const base='/api/v1'
export const session={
  get token(){return localStorage.getItem('winfire_access')},
  get refresh(){return localStorage.getItem('winfire_refresh')},
  setTokens(data){localStorage.setItem('winfire_access',data.accessToken);localStorage.setItem('winfire_refresh',data.refreshToken);localStorage.setItem('winfire_user',JSON.stringify(data.user))},
  clear(){localStorage.removeItem('winfire_access');localStorage.removeItem('winfire_refresh');localStorage.removeItem('winfire_user')},
  get user(){try{return JSON.parse(localStorage.getItem('winfire_user'))}catch{return null}}
}
export async function api(path,options={},retry=true){
  const response=await fetch(base+path,{...options,headers:{'Content-Type':'application/json',...(session.token?{Authorization:`Bearer ${session.token}`}:{}) ,...(options.headers||{})},body:options.body&&typeof options.body!=='string'?JSON.stringify(options.body):options.body})
  if(response.status===401&&retry&&session.refresh){
    const refresh=await fetch(base+'/auth/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refreshToken:session.refresh})})
    if(refresh.ok){session.setTokens(await refresh.json());return api(path,options,false)}
    session.clear();location.assign('/login');throw new Error('Session expired')
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
  let response=await fetch(base+path,{headers:{Authorization:`Bearer ${session.token}`}})
  if(response.status===401&&session.refresh){
    const refresh=await fetch(base+'/auth/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refreshToken:session.refresh})})
    if(refresh.ok){session.setTokens(await refresh.json());response=await fetch(base+path,{headers:{Authorization:`Bearer ${session.token}`}})}
  }
  if(!response.ok)throw new Error(`Export failed (${response.status})`)
  const url=URL.createObjectURL(await response.blob()),link=document.createElement('a')
  link.href=url;link.download=filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)
}
