<script setup>
import {ref,onMounted} from 'vue'
import {api} from '../services/api.js'
const settings=ref(null),credentials=ref([]),error=ref(''),message=ref(''),busy=ref(false),deliveries=ref({items:[],total:0}),page=ref(1)
async function load(){try{const [config,history]=await Promise.all([api('/notifications/servicenow'),api('/notifications/servicenow/deliveries?page='+page.value)]);settings.value=config.settings;credentials.value=config.credentials;deliveries.value=history;error.value=''}catch(e){error.value=e.message}}
async function action(fn){busy.value=true;error.value='';message.value='';try{await fn()}catch(e){error.value=e.message}finally{busy.value=false}}
async function save(){await action(async()=>{await api('/notifications/servicenow',{method:'PUT',body:settings.value});message.value='ServiceNow settings saved.'})}
async function test(){await action(async()=>{message.value=(await api('/notifications/servicenow/test',{method:'POST'})).message})}
async function retry(item){await action(async()=>{await api('/notifications/servicenow/deliveries/'+item.id+'/retry',{method:'POST'});await load()})}
onMounted(load)
</script>
<template><section class="integration-settings">
 <div class="panel-title"><h2>ServiceNow</h2><button class="button secondary" :disabled="busy" @click="load">Refresh</button></div>
 <p>Create incident tickets for the event categories selected in Destinations. Matching deliveries share one incident per event.</p>
 <p v-if="error" class="error-msg" role="alert">{{error}}</p><p v-if="message" class="success-msg" role="status">{{message}}</p>
 <form v-if="settings" class="integration-form" @submit.prevent="save">
  <label class="switch-field full"><span>Enable ServiceNow delivery</span><input v-model="settings.enabled" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label>
  <label>Instance URL<input v-model.trim="settings.baseUrl" type="url" placeholder="https://company.service-now.com" :required="settings.enabled"></label>
  <label>Vault credential<select v-model="settings.credentialId" :required="settings.enabled"><option value="">Select ServiceNow credential</option><option v-for="c in credentials" :value="c.id" :key="c.id">{{c.name}} · {{c.username}}</option></select><small>Create a ServiceNow username/password entry in <a href="/admin?tab=credentials">Credential vault</a>.</small></label>
  <label>Assignment group sys_id (optional)<input v-model.trim="settings.assignmentGroup" pattern="[a-fA-F0-9]{32}" maxlength="32" placeholder="32-character ServiceNow group ID"></label>
  <label>Impact<select v-model.number="settings.impact"><option :value="1">1 — High</option><option :value="2">2 — Medium</option><option :value="3">3 — Low</option></select></label>
  <label>Urgency<select v-model.number="settings.urgency"><option :value="1">1 — High</option><option :value="2">2 — Medium</option><option :value="3">3 — Low</option></select></label>
  <p class="full muted">Use a dedicated ServiceNow account with incident read/create permissions. TLS certificates are validated. Test checks the saved configuration and does not create a ticket.</p>
  <div class="form-actions full"><button class="button primary" :disabled="busy">Save integration</button><button type="button" class="button secondary" :disabled="busy" @click="test">Test saved connection</button></div>
 </form>
 <h3>Ticket deliveries</h3><p class="muted">Pending deliveries run every 30 seconds while enabled. Failures retry with backoff, up to five attempts.</p>
 <div class="table-wrap"><table><thead><tr><th>Event</th><th>Status</th><th>Ticket</th><th>Attempts</th><th>Last error</th><th>Actions</th></tr></thead><tbody><tr v-for="d in deliveries.items" :key="d.id"><td>{{d.title}}<small>{{d.category}}</small></td><td>{{d.status}}</td><td><a v-if="d.ticket" :href="d.ticket.instance_url+'/incident.do?sys_id='+d.ticket.sys_id" target="_blank" rel="noopener noreferrer">{{d.ticket.number||'Open incident'}}</a><span v-else>—</span></td><td>{{d.attempts}}</td><td>{{d.last_error||'—'}}</td><td><button v-if="d.status==='failed'" class="button small secondary" :disabled="busy" @click="retry(d)">Retry</button></td></tr><tr v-if="!deliveries.items.length"><td colspan="6">No ServiceNow deliveries yet.</td></tr></tbody></table></div>
 <div class="form-actions"><span>{{deliveries.total}} deliveries · Page {{page}}</span><button class="button secondary" :disabled="page===1||busy" @click="page--;load()">Previous</button><button class="button secondary" :disabled="page*25>=deliveries.total||busy" @click="page++;load()">Next</button></div>
</section></template>
<style scoped>
.integration-settings{padding:16px;min-width:0}.integration-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin:20px 0}.integration-form label{display:grid;align-content:start;gap:6px;min-width:0}.integration-form .switch-field{display:flex}.integration-form input,.integration-form select{width:100%;min-width:0}.full{grid-column:1/-1}small{display:block;color:var(--muted);margin-top:4px}.table-wrap{overflow-x:auto;max-width:100%}table{width:100%;min-width:600px}td{overflow-wrap:anywhere;max-width:45ch}.form-actions{flex-wrap:wrap}@media(max-width:650px){.integration-form{grid-template-columns:minmax(0,1fr)}}
</style>
