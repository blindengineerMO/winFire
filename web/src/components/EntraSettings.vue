<script setup>
import {onMounted,ref} from 'vue'
import {api} from '../lib/api.js'

const settings=ref({enabled:false,tenantId:'',clientId:'',clientSecretConfigured:false,redirectUris:[],ready:false,source:'environment'})
const secret=ref(''),busy=ref(false),error=ref(''),message=ref('')

async function load(){busy.value=true;error.value='';try{settings.value=await api('/settings/entra')}catch(cause){error.value=cause.message}finally{busy.value=false}}
async function save(){
  busy.value=true;error.value='';message.value=''
  try{
    const body={tenantId:settings.value.tenantId.trim(),clientId:settings.value.clientId.trim(),enabled:settings.value.enabled}
    if(secret.value)body.clientSecret=secret.value
    settings.value=await api('/settings/entra',{method:'PATCH',body})
    secret.value=''
    message.value='Microsoft Entra settings saved. Sign-in is ready when the app registration, redirect URIs, and MFA policy are configured.'
  }catch(cause){error.value=cause.message}
  finally{busy.value=false}
}
onMounted(load)
</script>

<template>
  <section class="entra-settings">
    <div class="panel-title"><div><span class="eyebrow">IDENTITY PROVIDER</span><h2>Microsoft Entra ID</h2></div><span class="status" :class="settings.ready?'reachable':'unknown'">{{settings.ready?'Configured':'Needs setup'}}</span></div>
    <p>Connect a single-tenant web app for MFA access requests. WinFire checks the tenant and requires an MFA claim before opening a temporary firewall rule.</p>
    <p v-if="settings.source==='environment'" class="muted">Values currently come from server environment variables. Saving here creates a database configuration that takes precedence.</p>
    <p v-if="error" class="error-msg" role="alert">{{error}}</p><p v-if="message" class="success-msg" role="status">{{message}}</p>
    <form class="form-grid" @submit.prevent="save">
      <label>Directory (tenant) ID<input v-model.trim="settings.tenantId" required autocomplete="off" placeholder="00000000-0000-0000-0000-000000000000"></label>
      <label>Application (client) ID<input v-model.trim="settings.clientId" required autocomplete="off" placeholder="00000000-0000-0000-0000-000000000000"></label>
      <label>Client secret <small>{{settings.clientSecretConfigured?'Stored securely; leave blank to keep it':'Required to enable sign-in'}}</small><input v-model="secret" type="password" autocomplete="new-password" :required="settings.enabled&&!settings.clientSecretConfigured" placeholder="Enter a new secret to rotate"></label>
      <label class="entra-toggle"><input v-model="settings.enabled" type="checkbox"> Enable Microsoft sign-in</label>
      <div class="form-actions"><button class="button primary" :disabled="busy">{{busy?'Saving…':'Save integration'}}</button></div>
    </form>
    <div class="entra-callbacks"><h3>Register these Web redirect URIs</h3><code v-for="uri in settings.redirectUris" :key="uri">{{uri}}</code><p v-if="!settings.redirectUris.length" class="muted">Set an HTTPS PUBLIC_BASE_URL on the server to show the redirect URIs.</p></div>
    <p class="muted">In the app registration, request the <code>amr</code> optional ID-token claim and require MFA with Conditional Access. WinFire uses OpenID Connect with PKCE. The secret stays on the server and is never returned to this page. A live tenant sign-in is still required to verify the integration.</p>
  </section>
</template>

<style scoped>
.entra-settings{padding:0 0 1.25rem;max-width:900px}.entra-settings>p,.entra-callbacks{margin:1rem 1.25rem;line-height:1.5}.entra-settings .form-grid{padding:0 1.25rem}.entra-settings label small{display:block;color:var(--muted);font-weight:400}.entra-settings .entra-toggle{display:flex;align-items:center;gap:.6rem}.entra-toggle input{width:17px;height:17px;flex:none}.entra-callbacks{padding:1rem;border:1px solid var(--border);border-radius:8px;overflow-wrap:anywhere}.entra-callbacks h3{margin:0 0 .65rem}.entra-callbacks code{display:block;margin:.35rem 0;font-size:.78rem;overflow-wrap:anywhere}.entra-settings .error-msg,.entra-settings .success-msg{margin:1rem 1.25rem}
</style>
