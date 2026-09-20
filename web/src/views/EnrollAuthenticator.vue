<script setup>
import {onMounted,ref} from 'vue'
import {useRoute} from 'vue-router'
import QRCode from 'qrcode'

const route=useRoute()
const brand=ref({companyName:'WinFire Secure',imageUrl:null})
const email=ref(''),password=ref(''),code=ref(''),working=ref(false),error=ref(''),step=ref('sign-in')
const enrollment=ref(null),qrImage=ref('')
const next=String(route.query.next||'')
const returnPath=/^\/mfa\/[0-9a-f-]{36}$/i.test(next)?next:'/login'

async function request(path,body){
  const response=await fetch(`/api/v1${path}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),cache:'no-store'})
  const data=await response.json().catch(()=>({error:'Request failed'}))
  if(!response.ok)throw new Error(data.error||'Request failed')
  return data
}
async function start(){
  error.value='';working.value=true
  try{
    enrollment.value=await request('/auth/ad-totp/enroll',{email:email.value.trim().toLowerCase(),password:password.value})
    password.value=''
    qrImage.value=await QRCode.toDataURL(enrollment.value.uri,{width:240,margin:2,errorCorrectionLevel:'M'})
    step.value='verify'
  }catch(cause){error.value=cause.message}
  finally{working.value=false}
}
async function confirm(){
  error.value='';working.value=true
  try{
    await request('/auth/ad-totp/confirm',{token:enrollment.value.token,code:code.value.trim()})
    enrollment.value=null;qrImage.value='';code.value='';step.value='done'
  }catch(cause){error.value=cause.message}
  finally{working.value=false}
}
onMounted(async()=>{try{const response=await fetch('/api/v1/portal-branding');if(response.ok)brand.value=await response.json()}catch{}})
</script>

<template>
  <main class="enroll-screen">
    <div class="enroll-art">
      <img :src="brand.imageUrl||'/winfire-mark.png'" alt="">
      <span>WINFIRE / SECURE</span>
      <h1>Protect your access.</h1>
      <p>Enroll an authenticator once, then use your AD credentials and a current code to approve protected connections.</p>
    </div>
    <section class="enroll-card" aria-labelledby="enroll-title">
      <span class="enroll-eyebrow">{{brand.companyName}} · MFA ENROLLMENT</span>
      <template v-if="step==='sign-in'">
        <h2 id="enroll-title">Enroll Authenticator</h2>
        <p>Sign in with your Active Directory account to create your authenticator setup.</p>
        <form @submit.prevent="start">
          <label>AD email or UPN<input v-model="email" type="email" autocomplete="username" placeholder="you@company.com" required></label>
          <label>AD password<input v-model="password" type="password" autocomplete="current-password" required></label>
          <button class="primary" :disabled="working">{{working?'Checking AD…':'Continue'}}</button>
        </form>
      </template>
      <template v-else-if="step==='verify'">
        <h2 id="enroll-title">Scan this code</h2>
        <p>In Google Authenticator or another authenticator app, add an account by scanning this QR code. Then enter the current six-digit code to finish.</p>
        <img class="enroll-qr" :src="qrImage" alt="Authenticator setup QR code">
        <details><summary>Can't scan the QR code?</summary><p>Choose manual entry in your app and enter this setup key:</p><code>{{enrollment.secret}}</code></details>
        <form @submit.prevent="confirm">
          <label>Authenticator code<input v-model="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000" required></label>
          <button class="primary" :disabled="working">{{working?'Verifying…':'Complete enrollment'}}</button>
        </form>
        <small>Setup expires in 10 minutes. Keep this QR code and key private.</small>
      </template>
      <template v-else>
        <div class="enroll-success"><i class="mdi mdi-check-circle-outline"></i></div>
        <h2 id="enroll-title">Authenticator enrolled</h2>
        <p>Your AD account is ready to approve protected access requests with its password and an authenticator code.</p>
        <a class="enroll-return primary" :href="returnPath">{{returnPath==='/login'?'Back to sign in':'Return to access request'}}</a>
      </template>
      <p v-if="error" class="enroll-error" role="alert">{{error}}</p>
      <a v-if="step!=='done'" class="enroll-back" :href="returnPath">{{returnPath==='/login'?'Back to sign in':'Return to access request'}}</a>
    </section>
  </main>
</template>

<style scoped>
.enroll-screen{min-height:100dvh;display:grid;grid-template-columns:minmax(0,1fr) minmax(330px,470px);gap:clamp(20px,5vw,90px);align-items:center;padding:clamp(24px,6vw,100px);background:linear-gradient(90deg,#f7fafbee,#f7fafb88 45%,#f7fafbcc),url('/enterprise-login-light.png') center/cover;color:#23384f}
.enroll-art{max-width:700px}.enroll-art img{width:85px;height:85px;object-fit:contain;display:block;margin-bottom:20px}.enroll-art span,.enroll-eyebrow{font-size:.68rem;letter-spacing:.15em;font-weight:800;color:#3b806b}.enroll-art h1{font-size:clamp(2.6rem,5vw,5rem);letter-spacing:-.055em;margin:14px 0}.enroll-art p{font-size:1rem;color:#3e586a;max-width:520px}
.enroll-card{background:#fffffff2;border:1px solid #d7e0e8;box-shadow:0 24px 70px #1e3c5a30;border-radius:16px;padding:clamp(24px,4vw,44px);display:flex;flex-direction:column;gap:15px}.enroll-card h2{font-size:1.7rem;margin:8px 0 0;color:#243952}.enroll-card p{font-size:.85rem;color:#435970;margin:0}.enroll-card form{display:grid;gap:16px}.enroll-card label{display:grid;gap:7px;font-size:.75rem;font-weight:700;color:#334d64}.enroll-card input{width:100%;height:44px;border:1px solid #aebecb;border-radius:6px;background:#fff;color:#1b3046;padding:0 12px}.enroll-card input:focus{outline:2px solid #557bbf;outline-offset:1px}.enroll-card .primary{height:46px;display:grid;place-items:center;border:0;border-radius:6px;background:#3d59a2;color:#fff;font-size:.83rem;font-weight:700;cursor:pointer}.enroll-card .primary:disabled{opacity:.6;cursor:wait}.enroll-card small{font-size:.68rem;color:#526579}.enroll-qr{width:220px;height:220px;max-width:100%;align-self:center;border:1px solid #dae1e7;border-radius:8px;background:#fff;padding:6px}.enroll-card details{font-size:.75rem;color:#3b5167}.enroll-card details p{margin:8px 0}.enroll-card code{display:block;word-break:break-all;font-size:.82rem;color:#183952;background:#eaf0f4;padding:9px;border-radius:4px}.enroll-error{background:#fbe7e9;border:1px solid #e8a9b1;border-radius:6px;color:#922f45!important;padding:10px}.enroll-back{text-align:center;color:#365bb1;font-size:.75rem;font-weight:700}.enroll-success{text-align:center;font-size:3rem;color:#25856c}.enroll-return{text-decoration:none}
@media(max-width:850px){.enroll-screen{grid-template-columns:1fr;gap:24px;padding:24px}.enroll-art h1{font-size:2.3rem}.enroll-art img{width:60px;height:60px;margin-bottom:12px}.enroll-card{max-width:520px;width:100%;justify-self:center}}
</style>
