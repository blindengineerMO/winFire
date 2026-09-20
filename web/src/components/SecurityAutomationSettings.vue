<script setup>
import {onMounted,ref} from 'vue'
import {api} from '../lib/api.js'

const policies=ref([]),incidents=ref([]),error=ref(''),message=ref(''),busy=ref(false),preview=ref(null)
const fresh=()=>({name:'',triggerType:'destination',destination:'',failureCount:3,windowMinutes:15,cooldownMinutes:60,actionType:'alert',disableMinutes:60,enabled:false})
const form=ref(fresh()),editing=ref(null)
const toForm=policy=>({name:policy.name,triggerType:policy.trigger_type,destination:policy.destination||'',failureCount:policy.failure_count,windowMinutes:policy.window_minutes,cooldownMinutes:policy.cooldown_minutes,actionType:policy.action_type,disableMinutes:policy.disable_minutes,enabled:!!policy.enabled})
async function load(){try{[policies.value,incidents.value]=await Promise.all([api('/security-automations'),api('/security-automations/incidents')])}catch(cause){error.value=cause.message}}
function edit(policy){editing.value=policy.id;form.value=toForm(policy);preview.value=null}
function clear(){editing.value=null;form.value=fresh();preview.value=null}
async function runPreview(){error.value='';try{preview.value=await api('/security-automations/preview',{method:'POST',body:form.value})}catch(cause){error.value=cause.message}}
async function save(){busy.value=true;error.value='';message.value='';try{const path=editing.value?`/security-automations/${editing.value}`:'/security-automations';await api(path,{method:editing.value?'PATCH':'POST',body:form.value});message.value='Security policy saved';clear();await load()}catch(cause){error.value=cause.message}finally{busy.value=false}}
async function toggle(policy){busy.value=true;error.value='';try{await api(`/security-automations/${policy.id}`,{method:'PATCH',body:{...toForm(policy),enabled:!policy.enabled}});await load()}catch(cause){error.value=cause.message}finally{busy.value=false}}
function incidentSummary(incident){try{return JSON.parse(incident.detail_json||'{}').summary||'—'}catch{return '—'}}
onMounted(load)
</script>

<template>
  <section class="security-automation">
    <div class="panel-title"><div><span class="eyebrow">SECURITY POLICY</span><h2>Automated responses</h2></div></div>
    <p>Match traffic to an IP address or a known inventory hostname, or count failed MFA challenges. Alerts use operator notification preferences. AD disable requires a recent outbound event on a WinRM-managed client, a verified process owner SID, and a separate LDAPS account-control credential.</p>
    <p class="muted">A submitted MFA username is not authenticated identity evidence, so repeated MFA failures can alert but cannot automatically disable an AD account. A logoff policy rechecks the active client session before ending it; if logoff fails, the AD hold remains active and an incident requests review.</p>
    <p v-if="error" class="error-msg" role="alert">{{error}}</p><p v-if="message" class="success-msg">{{message}}</p>
    <form class="automation-form" @submit.prevent="save">
      <label>Name<input v-model.trim="form.name" minlength="3" maxlength="120" required placeholder="Investigate RDP server access"></label>
      <label>When<select v-model="form.triggerType" @change="form.actionType='alert';preview=null"><option value="destination">Traffic reaches destination</option><option value="mfa_failures">Repeated MFA failures</option></select></label>
      <label v-if="form.triggerType==='destination'">Destination IP or inventory hostname<input v-model.trim="form.destination" required placeholder="192.0.2.10 or server.example.com"></label>
      <label v-else>Failure threshold<input v-model.number="form.failureCount" type="number" min="2" max="100" required></label>
      <label>Within minutes<input v-model.number="form.windowMinutes" type="number" min="1" max="1440" required></label>
      <label>Cooldown minutes<input v-model.number="form.cooldownMinutes" type="number" min="1" max="10080" required></label>
      <label>Action<select v-model="form.actionType"><option value="alert">Notify operators</option><option v-if="form.triggerType==='destination'" value="disable_ad">Temporarily disable matching AD user and notify</option><option v-if="form.triggerType==='destination'" value="disable_ad_logoff">Disable AD user, log off client, and notify</option></select></label>
      <label v-if="form.actionType!=='alert'">Disable for minutes<input v-model.number="form.disableMinutes" type="number" min="5" max="10080" required></label>
      <label class="automation-check"><input v-model="form.enabled" type="checkbox"> Enable after saving</label>
      <div class="automation-actions"><button type="button" class="button small secondary" :disabled="busy" @click="runPreview">Preview recent matches</button><button class="button small primary" :disabled="busy">{{editing?'Update policy':'Create policy'}}</button><button v-if="editing" type="button" class="button small secondary" @click="clear">Cancel edit</button></div>
    </form>
    <div v-if="preview" class="automation-preview"><p class="muted">{{preview.count}} recent matches shown. Preview does not run actions.</p><div v-if="preview.items.length" class="table-wrap"><table><thead><tr><th>TIME</th><th>SUBJECT</th><th>EVIDENCE</th></tr></thead><tbody><tr v-for="item in preview.items.slice(0,20)" :key="item.id||item.user_upn"><td>{{new Date(item.event_time||item.latest||item.received_at).toLocaleString()}}</td><td>{{item.user_upn||item.hostname||'—'}}</td><td>{{item.failures?`${item.failures} failures`:item.dst_ip||'—'}}</td></tr></tbody></table></div></div>
    <div class="table-wrap"><table><thead><tr><th>POLICY</th><th>TRIGGER</th><th>ACTION</th><th>STATUS</th><th>ACTIONS</th></tr></thead><tbody><tr v-for="policy in policies" :key="policy.id"><td>{{policy.name}}</td><td>{{policy.trigger_type==='destination'?policy.destination:`${policy.failure_count} MFA failures`}}</td><td>{{policy.action_type==='disable_ad_logoff'?`AD disable + logoff · ${policy.disable_minutes} min`:policy.action_type==='disable_ad'?`AD disable · ${policy.disable_minutes} min`:'Alert'}}</td><td>{{policy.enabled?'Enabled':'Paused'}}</td><td><button class="button small secondary" @click="edit(policy)">Edit</button> <button class="button small secondary" :disabled="busy" @click="toggle(policy)">{{policy.enabled?'Pause':'Enable'}}</button></td></tr><tr v-if="!policies.length"><td colspan="5">No security automations configured.</td></tr></tbody></table></div>
    <h3>Recent incidents</h3><div class="table-wrap"><table><thead><tr><th>TIME</th><th>POLICY</th><th>SUBJECT</th><th>RESULT</th><th>DETAIL</th></tr></thead><tbody><tr v-for="incident in incidents" :key="incident.id"><td>{{new Date(incident.created_at).toLocaleString()}}</td><td>{{incident.policy_name}}</td><td>{{incident.subject_key}}</td><td>{{incident.status}}</td><td>{{incidentSummary(incident)}}</td></tr><tr v-if="!incidents.length"><td colspan="5">No incidents recorded.</td></tr></tbody></table></div>
  </section>
</template>

<style scoped>
.security-automation{padding:1.2rem;border-top:1px solid var(--border)}.security-automation>p{max-width:850px;font-size:.8rem}.automation-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(205px,1fr));gap:.7rem;margin:1rem 0}.automation-form label{display:grid;gap:.3rem;font-size:.75rem}.automation-form input,.automation-form select{width:100%;box-sizing:border-box}.automation-form .automation-check{display:flex;align-items:center;gap:.5rem}.automation-check input{width:auto}.automation-actions{grid-column:1/-1;display:flex;flex-wrap:wrap;gap:.5rem}.security-automation h3{margin-top:1.4rem}
</style>
