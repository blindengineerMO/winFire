<script setup>
import {ref} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {api,session} from '../services/api.js'

const route=useRoute(),router=useRouter(),error=ref(''),working=ref(false),verified=ref(false)
async function verify(){
  working.value=true;error.value=''
  try{await api('/auth/verify-email',{method:'POST',body:{token:String(route.query.token||'')}});session.clear();verified.value=true}
  catch(e){error.value=e.message}
  finally{working.value=false}
}
</script>

<template><div class="login-screen"><div class="login-art"><span class="eyebrow">WINFIRE / SECURE</span><div class="login-symbol"><i class="mdi mdi-email-check-outline"></i></div><h1>Confirm your<br><em>email address.</em></h1><p>Verify the address you will use to sign in.</p><div class="login-grid"></div></div><div class="login-form glass"><span class="eyebrow">ACCOUNT SECURITY</span><h2>{{verified?'Email verified':'Verify email'}}</h2><p>{{verified?'Sign in again to continue.':'Use the link from your verification message.'}}</p><div v-if="error" class="error-msg">{{error}}</div><button v-if="verified" class="primary" @click="router.push('/login')">Sign in <i class="mdi mdi-arrow-right"></i></button><button v-else class="primary" :disabled="working||!route.query.token" @click="verify">{{working?'Verifying…':'Verify address'}} <i class="mdi mdi-arrow-right"></i></button></div></div></template>
