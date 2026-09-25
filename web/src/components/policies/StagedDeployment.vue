<script setup>
import {ref,computed,onMounted,onUnmounted,watch} from 'vue'
import {api,session} from '../../services/api.js'
const props=defineProps({policy:Object})
const simulations=ref([]),jobs=ref([]),simulationId=ref(''),canaries=ref([]),batchSize=ref(1),maxFailures=ref(0),recoverySeconds=ref(600),ports=ref('443'),reason=ref(''),actionReason=ref(''),preview=ref(null),selected=ref(null),busy=ref(false),error=ref('')
const windowStart=ref(localTime(Date.now())),windowEnd=ref(localTime(Date.now()+3600000))
const admin=computed(()=>['owner','admin'].includes(session.user?.role))
const reviewed=computed(()=>simulations.value.filter(s=>s.status==='completed'&&s.approvalValid))
const targets=computed(()=>reviewed.value.find(s=>s.id===simulationId.value)?.snapshot?.nodes||[])
const targetIds=computed(()=>reviewed.value.find(s=>s.id===simulationId.value)?.snapshot?.nodeIds||[])
const canQueue=computed(()=>preview.value&&preview.value.targets.every(t=>t.supported&&t.pilotEnabled))
let timer
function localTime(value){const d=new Date(value);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16)}
function input(){return {simulationId:simulationId.value,canaryNodeIds:canaries.value,batchSize:batchSize.value,maxFailures:maxFailures.value,recoverySeconds:recoverySeconds.value,healthPorts:ports.value.split(',').map(p=>Number(p.trim())),windowStart:new Date(windowStart.value).toISOString(),windowEnd:new Date(windowEnd.value).toISOString(),reason:reason.value}}
async function load(){try{const [s,j]=await Promise.all([api(`/policies/${props.policy.id}/simulations`),api(`/policies/${props.policy.id}/deployments`)]);simulations.value=s;jobs.value=j;if(selected.value)selected.value=j.find(x=>x.id===selected.value.id)||null}catch(e){error.value=e.message}}
async function inspect(){busy.value=true;error.value='';preview.value=null;try{preview.value=await api('/policy-deployments/preview',{method:'POST',body:input()})}catch(e){error.value=e.message}finally{busy.value=false}}
async function queue(){if(!canQueue.value)return;busy.value=true;error.value='';try{selected.value=await api('/policy-deployments',{method:'POST',body:input()});preview.value=null;await load()}catch(e){error.value=e.message}finally{busy.value=false}}
async function action(name){busy.value=true;error.value='';try{selected.value=await api(`/policy-deployments/${selected.value.id}/${name}`,{method:'POST',body:{reason:actionReason.value}});actionReason.value='';await load()}catch(e){error.value=e.message}finally{busy.value=false}}
watch([simulationId,canaries,batchSize,maxFailures,recoverySeconds,ports,reason,windowStart,windowEnd],()=>{preview.value=null},{deep:true})
watch(simulationId,()=>{canaries.value=[]})
onMounted(()=>{load();timer=setInterval(()=>{if(jobs.value.some(j=>['queued','running','cancelling','restoring'].includes(j.status)))load()},3000)})
onUnmounted(()=>clearInterval(timer))
</script>
<template>
<section class="panel glass"><div class="panel-title"><h2>Staged deployment</h2><button class="button secondary" @click="load">Refresh</button></div><div class="staging-body">
<p class="muted">Preview canaries, application health checks and recovery before starting a rollout. Native Windows recovery is available for explicitly configured pilot hosts. Production deployment remains gated pending live recovery validation.</p>
<p v-if="error" class="error-msg" role="alert">{{error}}</p>
<form v-if="admin" class="staging-form" @submit.prevent="inspect">
<label>Reviewed evaluation<select v-model="simulationId" required><option value="">Select evaluation</option><option v-for="s in reviewed" :key="s.id" :value="s.id">{{new Date(s.created_at).toLocaleString()}} · {{s.processed}} observations</option></select></label>
<label>Canary assets<select v-model="canaries" multiple required aria-label="Canary assets"><option v-for="id in targetIds" :key="id" :value="id">{{targets.find(n=>n.id===id)?.hostname||id}}</option></select></label>
<label>Application TCP ports<input v-model="ports" placeholder="443, 8443" required><small>Checked from the API server before and after each change.</small></label>
<label>Nodes per later batch<input v-model.number="batchSize" type="number" min="1" max="10" required></label>
<label>Recovery window (seconds)<input v-model.number="recoverySeconds" type="number" min="300" max="3600" required></label>
<label>Allowed later-batch failures<input v-model.number="maxFailures" type="number" min="0" max="100" required><small>Any canary failure or failed restore always pauses deployment.</small></label>
<label>Start window<input v-model="windowStart" type="datetime-local" required></label><label>End window<input v-model="windowEnd" type="datetime-local" required></label>
<label>Deployment reason<input v-model="reason" maxlength="2000" required></label>
<div class="staging-actions"><button class="button secondary" :disabled="busy||!simulationId||!canaries.length">Preview rollout</button></div>
</form>
<p v-if="admin&&!reviewed.length" class="muted">Complete and review a policy impact evaluation to preview a rollout.</p>
<template v-if="preview"><h3>Rollout preview</h3><p v-if="preview.retirementExceptions.length">{{preview.retirementExceptions.length}} exception records will be retired only after every target confirms deployment. Partial or offline outcomes remain pending.</p><p>{{preview.batches.length}} batches. The first batch contains the canaries.</p><div class="table-wrap"><table><thead><tr><th>Asset</th><th>Transport</th><th>Recovery readiness</th></tr></thead><tbody><tr v-for="t in preview.targets" :key="t.nodeId"><td>{{t.hostname}}</td><td>{{t.transport}}</td><td>{{t.reason||'Authorized pilot — native recovery will be armed before changes'}}</td></tr></tbody></table></div><button class="button primary" :disabled="busy||!canQueue" @click="queue">Start staged rollout</button></template>
<div class="table-wrap"><table><thead><tr><th>Started</th><th>Status</th><th>Batch</th><th>Reason / outcome</th><th></th></tr></thead><tbody><tr v-for="j in jobs" :key="j.id"><td>{{new Date(j.created_at).toLocaleString()}}</td><td>{{j.status}}</td><td>{{j.next_batch+1}}</td><td>{{j.error||j.config.reason}}</td><td><button class="button small secondary" @click="selected=j">Details</button></td></tr><tr v-if="!jobs.length"><td colspan="5">No staged deployments.</td></tr></tbody></table></div>
<template v-if="selected"><h3>Per-asset outcomes</h3><p v-if="selected.error" role="status">{{selected.error}}</p><div class="table-wrap"><table><thead><tr><th>Asset</th><th>Status</th><th>Host recovery</th><th>Health / error</th></tr></thead><tbody><tr v-for="t in selected.targets" :key="t.node_id"><td>{{t.node_id}}</td><td>{{t.status}}</td><td>{{t.snapshot?.phase||'Not armed'}}<small v-if="t.snapshot?.expiresAt">{{new Date(t.snapshot.expiresAt).toLocaleString()}}</small></td><td>{{t.error||t.health?.checks?.map(c=>`${c.port}: ${c.status}`).join(' · ')||'Not checked'}}</td></tr></tbody></table></div><div v-if="admin&&!['restored','cancelled'].includes(selected.status)" class="staging-actions"><input v-model="actionReason" maxlength="2000" placeholder="Action reason" aria-label="Deployment action reason"><button v-if="['paused','partial'].includes(selected.status)" class="button secondary" :disabled="busy||!actionReason.trim()" @click="action('resume')">Resume rollout</button><button class="button danger" :disabled="busy||!actionReason.trim()" @click="action(selected.status==='completed'?'restore':'cancel')">{{selected.status==='completed'?'Restore previous rules':'Cancel and restore'}}</button></div></template>
</div></section>
</template>
<style scoped>
.staging-body{padding:16px;min-width:0}.staging-form{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:16px 0}.staging-form label{display:grid;align-content:start;gap:6px}.staging-actions{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin:12px 0}.table-wrap{max-width:100%;overflow:auto;margin:16px 0}table{width:100%}td{max-width:50ch;overflow-wrap:anywhere}small{display:block;color:var(--muted)}@media(max-width:850px){.staging-form{grid-template-columns:1fr}}
</style>
