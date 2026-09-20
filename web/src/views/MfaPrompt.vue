<script setup>
import {onMounted,ref,computed} from 'vue'
import {useRoute} from 'vue-router'

const route=useRoute()
const brand=ref({companyName:'WinFire Secure',imageUrl:null})
const prompt=ref(null),loading=ref(true),working=ref(false),showAuthenticator=ref(false)
const email=ref(''),password=ref(''),code=ref(''),error=ref(''),approved=ref(null)
const callback=computed(()=>route.path==='/mfa/callback')
const resourceLabel=computed(()=>prompt.value?.protocol==='TCP'?`TCP port ${prompt.value.port}`:`${prompt.value.protocol} on port ${prompt.value.port}`)

async function publicApi(path,options={}){
  const response=await fetch(`/api/v1${path}`,{...options,headers:{'Content-Type':'application/json'},body:options.body?JSON.stringify(options.body):undefined})
  const data=await response.json().catch(()=>({error:'Request failed'}))
  if(!response.ok)throw new Error(data.error||'Request failed')
  return data
}
async function loadPrompt(promptId){prompt.value=await publicApi(`/mfa/prompts/${promptId}`);brand.value=prompt.value.branding||brand.value}
async function startMicrosoft(){
  if(!prompt.value)return
  error.value='';working.value=true
  try{
    const started=await publicApi(`/mfa/prompts/${prompt.value.id}/entra/start`,{method:'POST'})
    const state=new URL(started.authorizationUrl).searchParams.get('state')
    if(state)sessionStorage.setItem('winfire_mfa_redirect',JSON.stringify({state,promptId:prompt.value.id}))
    window.location.assign(started.authorizationUrl)
  }catch(cause){error.value=cause.message;working.value=false}
}
async function submitAuthenticator(){
  if(!prompt.value)return
  error.value='';working.value=true
  try{approved.value=await publicApi(`/mfa/prompts/${prompt.value.id}/totp`,{method:'POST',body:{email:email.value.trim().toLowerCase(),password:password.value,code:code.value.trim()}});password.value='';code.value=''}
  catch(cause){error.value=cause.message}
  finally{working.value=false}
}
async function completeMicrosoft(){
  const state=String(route.query.state||''),authorizationCode=String(route.query.code||''),providerError=String(route.query.error||'')
  let saved=null
  try{saved=JSON.parse(sessionStorage.getItem('winfire_mfa_redirect')||'null')}catch{sessionStorage.removeItem('winfire_mfa_redirect')}
  if(saved?.state===state&&saved.promptId)try{await loadPrompt(saved.promptId)}catch{}
  window.history.replaceState({},'',route.path)
  try{
    if(providerError){
      if(state&&/^[A-Za-z0-9_]{1,64}$/.test(providerError))await publicApi('/mfa/entra/cancel',{method:'POST',body:{state,error:providerError}})
      throw new Error('Microsoft sign-in was cancelled or denied. Return to the request and try again.')
    }
    if(!state||!authorizationCode)throw new Error('The Microsoft sign-in response is incomplete.')
    approved.value=await publicApi('/mfa/entra/complete',{method:'POST',body:{state,code:authorizationCode}})
    sessionStorage.removeItem('winfire_mfa_redirect')
  }catch(cause){error.value=cause.message}
}
onMounted(async()=>{
  try{
    brand.value=await publicApi('/portal-branding')
    if(callback.value)await completeMicrosoft()
    else await loadPrompt(String(route.params.promptId||''))
  }catch(cause){error.value=cause.message}
  finally{loading.value=false}
})
</script>

<template>
  <main class="mfa-screen">
    <div class="mfa-column">
      <header class="mfa-brand">
        <img :src="brand.imageUrl||'/winfire-mark.png'" :alt="brand.imageUrl?`${brand.companyName} logo`:'WinFire Secure logo'">
        <strong>{{brand.companyName}}</strong>
        <span>SECURE ACCESS</span>
      </header>

      <div v-if="loading" class="mfa-request mfa-loading" role="status">Loading your access request…</div>
      <template v-else-if="approved">
        <div class="mfa-result-icon"><i class="mdi mdi-check"></i></div>
        <h1>Access approved</h1>
        <p class="mfa-intro">Retry your connection now. Temporary access is open for your current source address until {{new Date(approved.expiresAt).toLocaleString()}}.</p>
        <div class="mfa-request"><span>PROTECTED CONNECTION</span><strong>{{approved.sourceIp}} → TCP {{approved.port}}</strong></div>
      </template>
      <template v-else>
        <h1>Approve this access request</h1>
        <div v-if="prompt" class="mfa-request">
          <span>CONNECTION REQUEST</span>
          <p><strong>{{prompt.sessionUser||'A user on this device'}}</strong> is trying to access <strong>{{prompt.target}}</strong> from <strong>{{prompt.source}}</strong> over <strong>{{resourceLabel}}</strong>.</p>
          <div v-if="prompt.program" class="mfa-program"><i class="mdi mdi-application-outline"></i><span>{{prompt.program}}</span></div>
          <small>Session {{prompt.sessionId??'unknown'}} · Request expires {{new Date(prompt.expiresAt).toLocaleTimeString()}}</small>
        </div>
        <p v-if="prompt" class="mfa-intro">Sign in to authorize this request. Access will close automatically after {{prompt.ttlMinutes}} minutes.</p>
        <p v-else-if="!error" class="mfa-intro">Your access request is no longer available.</p>

        <div v-if="error" class="mfa-error" role="alert">{{error}}</div>
        <template v-if="prompt?.provider==='entra'">
          <button class="mfa-action" :disabled="working||!prompt.providerAvailable" @click="startMicrosoft"><span class="microsoft-mark"><i></i><i></i><i></i><i></i></span>{{working?'Opening Microsoft…':'Sign in with Microsoft'}}</button>
          <small v-if="!prompt.providerAvailable" class="mfa-availability">Microsoft sign-in is not configured for this environment.</small>
        </template>
        <template v-else-if="prompt?.provider==='totp'">
          <button v-if="!showAuthenticator" class="mfa-action" :disabled="!prompt.providerAvailable" @click="showAuthenticator=true"><i class="mdi mdi-shield-key-outline"></i> Sign in with AD + Authenticator</button>
          <small v-if="!prompt.providerAvailable" class="mfa-availability">AD sign-in requires a working LDAPS connection.</small>
          <form v-if="showAuthenticator" class="mfa-form" @submit.prevent="submitAuthenticator">
            <label>AD email or UPN<input v-model="email" type="email" autocomplete="username" placeholder="you@company.com" required></label>
            <label>AD password<input v-model="password" type="password" autocomplete="current-password" required></label>
            <label>Google Authenticator code<input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000" required></label>
            <button class="mfa-action" :disabled="working||!prompt.providerAvailable"><i class="mdi mdi-shield-check-outline"></i> {{working?'Verifying…':'Authorize access'}}</button>
          </form>
          <a class="mfa-return" :href="`/enroll-authenticator?next=${encodeURIComponent(`/mfa/${prompt.id}`)}`">New to AD + Authenticator? Enroll here</a>
        </template>
        <a v-if="callback&&error&&prompt" class="mfa-return" :href="`/mfa/${prompt.id}`">Return to request</a>
      </template>
      <footer class="mfa-footer"><i class="mdi mdi-lock-outline"></i> Your sign-in is checked for this request and recorded in the audit trail.</footer>
    </div>
  </main>
</template>

<style scoped>
.mfa-screen{min-height:100dvh;background:#e9edf1;color:#26364a;display:flex;justify-content:center;font-family:Arial,Helvetica,sans-serif}
.mfa-column{width:min(100%,510px);min-height:100dvh;padding:clamp(26px,5vw,46px);background:#f9fafb;border-inline:1px solid #cdd8e2;box-shadow:0 14px 50px #32475e13;display:flex;flex-direction:column;align-items:stretch;min-width:0}
.mfa-brand{display:flex;align-items:center;flex-direction:column;text-align:center;gap:5px;margin:0 0 clamp(35px,7vh,70px)}
.mfa-brand img{height:75px;max-width:min(240px,100%);object-fit:contain;margin-bottom:5px}
.mfa-brand strong{font-size:1.25rem;letter-spacing:-.02em;color:#253650;overflow-wrap:anywhere}
.mfa-brand span{font-size:.64rem;letter-spacing:.17em;font-weight:800;color:#568d81}
h1{margin:0 0 22px;font-size:1.45rem;line-height:1.2;color:#223650;letter-spacing:-.025em;text-align:center}
.mfa-request{padding:19px 20px;border:1px solid #d9e1e7;border-radius:10px;background:#f0f3f5;min-width:0}
.mfa-request>span{display:block;margin-bottom:12px;font-size:.63rem;letter-spacing:.14em;font-weight:800;color:#608476}
.mfa-request p{margin:0;color:#2a3c52;font-size:.94rem;line-height:1.7;overflow-wrap:anywhere}
.mfa-request p strong{color:#365bb1;font-weight:700}
.mfa-request small{display:block;margin-top:15px;color:#697a89;font-size:.7rem;line-height:1.45}
.mfa-program{display:flex;align-items:start;gap:7px;margin-top:12px;color:#435c76;font-size:.75rem;overflow-wrap:anywhere;min-width:0}
.mfa-program i{flex:none;color:#678b85}
.mfa-program span{min-width:0}
.mfa-intro{font-size:.91rem;line-height:1.55;margin:24px 0 17px;color:#34475c;text-align:center}
.mfa-action{width:100%;min-height:48px;display:flex;align-items:center;justify-content:center;gap:10px;border:1px solid #bbc8d5;border-radius:8px;background:#fff;color:#365ab2;box-shadow:0 2px 4px #334a5b12;font:700 .87rem Arial,Helvetica,sans-serif;cursor:pointer;padding:10px 14px}
.mfa-action:hover:not(:disabled){background:#eef4ff;border-color:#7996d5}
.mfa-action:focus-visible{outline:3px solid #7594db;outline-offset:2px}
.mfa-action:disabled{opacity:.53;cursor:not-allowed}
.mfa-action .mdi{font-size:1.25rem;color:#3d8a74}
.microsoft-mark{width:19px;height:19px;display:grid;grid-template-columns:repeat(2,1fr);gap:2px;flex:none}
.microsoft-mark i:nth-child(1){background:#f35325}.microsoft-mark i:nth-child(2){background:#81bc06}.microsoft-mark i:nth-child(3){background:#05a6f0}.microsoft-mark i:nth-child(4){background:#ffba08}
.mfa-availability{display:block;text-align:center;color:#7b5662;font-size:.73rem;margin-top:10px}
.mfa-form{display:grid;gap:13px;margin-top:6px}
.mfa-form label{display:grid;gap:6px;font-size:.74rem;font-weight:700;color:#43566d}
.mfa-form input{width:100%;height:43px;padding:0 11px;border:1px solid #b7c7d3;border-radius:6px;background:#fff;color:#263b56;font:inherit}
.mfa-form input:focus{outline:2px solid #7391d4;outline-offset:1px}
.mfa-form .mfa-action{margin-top:4px;background:#3d5fb6;color:#fff;border-color:#3d5fb6}
.mfa-form .mfa-action .mdi{color:#fff}
.mfa-form .mfa-action:hover:not(:disabled){background:#304fa1}
.mfa-error{margin:0 0 15px;padding:12px 14px;border:1px solid #e0a4af;border-radius:7px;background:#fbe9ed;color:#923448;font-size:.78rem;line-height:1.45;overflow-wrap:anywhere}
.mfa-loading{text-align:center;color:#536b80}
.mfa-result-icon{width:58px;height:58px;margin:0 auto 18px;border-radius:50%;display:grid;place-items:center;background:#d9f2e8;color:#218267;font-size:2rem}
.mfa-return{margin-top:12px;color:#365bb1;font-size:.77rem;font-weight:700;text-align:center}
.mfa-footer{margin-top:auto;padding-top:45px;text-align:center;color:#7b8a99;font-size:.67rem;line-height:1.5}
.mfa-footer i{color:#598e82}
@media(max-width:540px){.mfa-column{border:0;padding:24px 20px 30px}.mfa-brand{margin-bottom:35px}.mfa-request{padding:16px}.mfa-request p{font-size:.89rem}.mfa-footer{padding-top:36px}}
</style>
