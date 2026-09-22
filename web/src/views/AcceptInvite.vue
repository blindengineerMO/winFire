<script setup>
import {ref} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {api} from '../services/api.js'

const route=useRoute(),router=useRouter()
const password=ref(''),confirm=ref(''),error=ref(''),working=ref(false),done=ref(false)
async function accept(){
  error.value=''
  if(password.value!==confirm.value){error.value='Passwords do not match';return}
  working.value=true
  try{
    await api('/invites/accept',{method:'POST',body:{token:String(route.query.token||''),password:password.value}})
    done.value=true
  }catch(e){error.value=e.message}
  finally{working.value=false}
}
</script>

<template>
  <div class="login-screen">
    <div class="login-art"><span class="eyebrow">WINFIRE / SECURE</span><div class="login-symbol"><i class="mdi mdi-account-plus-outline"></i></div><h1>Join the<br><em>control plane.</em></h1><p>Finish setting up your operator account.</p><div class="login-grid"></div></div>
    <div v-if="done" class="login-form glass"><span class="eyebrow">INVITATION ACCEPTED</span><h2>Account ready</h2><p>You can now sign in with your email and new password.</p><button class="primary" @click="router.push('/login')">Sign in <i class="mdi mdi-arrow-right"></i></button></div>
    <form v-else class="login-form glass" @submit.prevent="accept"><span class="eyebrow">OPERATOR ACCESS</span><h2>Accept invitation</h2><p>Choose a password for your account.</p><label>New password<input v-model="password" type="password" autocomplete="new-password" minlength="12" required></label><label>Confirm password<input v-model="confirm" type="password" autocomplete="new-password" minlength="12" required></label><div v-if="error" class="error-msg">{{error}}</div><button class="primary" :disabled="working||!route.query.token">{{working?'Creating account…':'Create account'}} <i class="mdi mdi-arrow-right"></i></button><small v-if="!route.query.token">Open the invitation link you received to continue.</small></form>
  </div>
</template>
