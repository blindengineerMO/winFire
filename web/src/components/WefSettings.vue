<script setup>
import {computed,onMounted,ref} from 'vue'
import {api} from '../services/api.js'

const settings=ref({enabled:false,secretConfigured:false,secretSource:'unset',baseUrl:null,path:'/api/v1/wef/wsman'})
const nodes=ref([]),nodeId=ref(''),refreshSeconds=ref(900),sharedSecret=ref(''),clearSecret=ref(false),busy=ref(false),error=ref(''),message=ref(''),result=ref(null)
const eligible=computed(()=>nodes.value.filter(node=>node.connection_mode==='agentless'&&['winrm','winrms'].includes(node.transport)))
async function load(){
  try{const [wef,inventory]=await Promise.all([api('/settings/wef'),api('/nodes')]);settings.value=wef;nodes.value=inventory}catch(cause){error.value=cause.message}
}
async function save(){
  busy.value=true;error.value='';message.value=''
  try{const body={enabled:settings.value.enabled};if(sharedSecret.value)body.sharedSecret=sharedSecret.value;if(clearSecret.value)body.clearSecret=true;settings.value=await api('/settings/wef',{method:'PATCH',body});sharedSecret.value='';clearSecret.value=false;message.value=settings.value.enabled?'WEF push receiver enabled':'WEF push receiver disabled'}catch(cause){error.value=cause.message}finally{busy.value=false}
}
async function configure(){
  if(!nodeId.value)return
  busy.value=true;error.value='';message.value='';result.value=null
  try{result.value=await api(`/nodes/${nodeId.value}/wef/configure`,{method:'POST',body:{refreshSeconds:Number(refreshSeconds.value)}});message.value=`WEF source configured on ${nodes.value.find(node=>node.id===nodeId.value)?.hostname||nodeId.value}`}catch(cause){error.value=cause.message}finally{busy.value=false}
}
onMounted(load)
</script>

<template>
  <section class="wef-settings">
    <h3>Windows Event Forwarding (WEF)</h3>
    <p class="muted">Source-initiated WEF sends Security firewall and logon events to the embedded WS-Man receiver. The receiver authenticates each source with a node-scoped token and keeps WinRM pull collection available as a fallback.</p>
    <p v-if="error" class="error-msg" role="alert">{{error}}</p><p v-if="message" class="success-msg" role="status">{{message}}</p>
    <div class="wef-status"><span class="status" :class="settings.enabled&&settings.secretConfigured?'reachable':'unknown'">{{settings.enabled?'Enabled':'Disabled'}}</span><span>{{settings.secretConfigured?'Shared secret configured':'Configure a shared secret below'}}</span><small>Source: {{settings.secretSource}}</small><code>{{settings.baseUrl||'PUBLIC_BASE_URL'}}{{settings.path}}</code></div>
    <div class="wef-secret-form"><label>Shared secret<input v-model="sharedSecret" type="password" minlength="8" maxlength="512" autocomplete="new-password" :disabled="settings.secretSource==='environment'||busy" :placeholder="settings.secretSource==='environment'?'Managed by WEF_SHARED_SECRET':'Enter a new secret'"><small v-if="settings.secretSource==='environment'">The environment value takes precedence. Remove WEF_SHARED_SECRET from the deployment environment to manage it here.</small><small v-else>Stored encrypted and never shown again. Leave blank to keep the existing value.</small></label><label v-if="settings.secretSource==='administration'" class="check-label"><input v-model="clearSecret" type="checkbox" :disabled="busy||!!sharedSecret"> Clear the saved shared secret</label></div>
    <div class="inline-actions"><label class="check-label"><input v-model="settings.enabled" type="checkbox"> Enable push receiver</label><button class="button small primary" :disabled="busy||!settings.secretConfigured&&!sharedSecret&&!clearSecret" @click="save">Save receiver setting</button></div>
    <form class="wef-configure" @submit.prevent="configure">
      <h4>Configure a source node</h4>
      <label>WinRM node<select v-model="nodeId" required><option value="">Select a node</option><option v-for="node in eligible" :key="node.id" :value="node.id">{{node.hostname}} · {{node.status}}</option></select></label>
      <label>Refresh interval (seconds)<input v-model.number="refreshSeconds" type="number" min="60" max="86400" required></label>
      <button class="button small secondary" :disabled="busy||!settings.enabled||!settings.secretConfigured||!nodeId">{{busy?'Configuring…':'Configure source over WinRM'}}</button>
    </form>
    <pre v-if="result" class="code-block">{{JSON.stringify(result,null,2)}}</pre>
  </section>
</template>

<style scoped>
.wef-settings{border-top:1px solid var(--border);padding:1.2rem 0;display:grid;gap:.7rem}.wef-settings h3,.wef-configure h4{margin:0}.wef-settings p{margin:.2rem 0}.wef-status{display:flex;align-items:center;gap:.65rem;flex-wrap:wrap;padding:.7rem;border:1px solid var(--border);border-radius:7px}.wef-status code{font-size:.65rem;overflow-wrap:anywhere;color:var(--muted)}.wef-secret-form{display:grid;gap:.5rem;padding:.8rem;border:1px solid var(--border);border-radius:7px}.wef-secret-form label{display:grid;gap:.3rem;font-size:.75rem}.wef-secret-form small{color:var(--muted)}.wef-configure{display:grid;grid-template-columns:minmax(180px,1fr) 180px auto;align-items:end;gap:.7rem;padding:.9rem;border:1px solid var(--border);border-radius:7px}.wef-configure h4{grid-column:1/-1}.wef-configure label{display:grid;gap:.3rem;font-size:.75rem}.wef-configure button{height:36px}@media(max-width:700px){.wef-configure{grid-template-columns:1fr}.wef-configure h4{grid-column:auto}}
</style>
