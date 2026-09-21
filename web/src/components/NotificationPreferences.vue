<script setup>
import {ref,watch} from 'vue'
import {api,session} from '../lib/api.js'

const props=defineProps({me:{type:Object,default:null}})
const categories=[['policy_drift','Policy drift'],['verifier_failure','Verifier failure'],['mfa_access_request','MFA access request'],['mfa_challenge_failure','MFA challenge failure'],['agent_offline','Agent offline'],['node_unreachable','Node unreachable'],['security_policy','Security policy']]
const channels=[['in_app','In app'],['email','Email'],['webhook','Webhook']]
const preferences=ref({}),saving=ref(false),error=ref(''),message=ref('')
watch(()=>props.me?.profile?.notification_prefs,value=>{
  let saved={}
  try{saved=JSON.parse(value||'{}')||{}}catch{}
  preferences.value=Object.fromEntries(categories.flatMap(([category])=>channels.map(([channel])=>[`${category}.${channel}`,saved[`${category}.${channel}`]??(channel==='in_app')])))
},{immediate:true})
async function save(){
  saving.value=true;error.value='';message.value=''
  try{await api(`/users/${session.user.id}/profile`,{method:'PATCH',body:{notificationPrefs:preferences.value}});message.value='Notification preferences saved'}
  catch(cause){error.value=cause.message}
  finally{saving.value=false}
}
</script>
<template>
  <section class="notification-preferences">
    <h3>Notifications</h3>
    <p>Choose which security events reach you. In-app alerts appear in the bell at the top of the page.</p>
    <div class="notification-preferences-table" role="group" aria-label="Notification channels by category">
      <div class="notification-preferences-head"><span>Event</span><span v-for="[channel,name] in channels" :key="name"><span class="desktop-channel">{{name}}</span><span class="mobile-channel">{{channel==='in_app'?'App':channel==='webhook'?'Hook':'Email'}}</span></span></div>
      <div v-for="[category,label] in categories" :key="category" class="notification-preferences-row">
        <strong>{{label}}</strong>
        <label v-for="[channel,name] in channels" :key="channel" :title="`${label}: ${name}`"><input v-model="preferences[`${category}.${channel}`]" type="checkbox" :aria-label="`${label}: ${name}`" :disabled="channel==='email'&&!me?.emailVerified"> <span class="mobile-channel">{{name}}</span></label>
      </div>
    </div>
    <p v-if="!me?.emailVerified" class="notification-note">Verify your email address to enable email alerts.</p>
    <p class="notification-note">Email delivery requires SMTP. Webhook delivery uses the server's configured HTTPS endpoint.</p>
    <div v-if="error" class="error-msg">{{error}}</div><div v-if="message" class="success-msg">{{message}}</div>
    <button class="button small secondary" :disabled="saving" @click="save">Save notification preferences</button>
  </section>
</template>
