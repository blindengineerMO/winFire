<script setup>
import {onMounted,ref} from 'vue'
import {api} from '../lib/api.js'
import GlassWindow from './GlassWindow.vue'

const rules=ref([]),busy=ref(false),error=ref(''),message=ref(''),cleanupOpen=ref(false),cleanupConfirmed=ref(false),cleanupBusy=ref(false)
const blank=()=>({label:'',eventId:5157,action:'',protocol:'',direction:'',srcIp:'',dstIp:'',dstPort:'',program:'',accountSids:''})
const form=ref(blank())
async function load(){try{rules.value=await api('/settings/traffic-ignores');error.value=''}catch(cause){error.value=cause.message}}
async function create(){busy.value=true;error.value='';message.value='';try{const accountSids=form.value.accountSids.split(/[\n,]+/).map(value=>value.trim()).filter(Boolean);const result=await api('/settings/traffic-ignores',{method:'POST',body:{...form.value,eventId:Number(form.value.eventId),dstPort:form.value.dstPort?Number(form.value.dstPort):null,srcIp:form.value.srcIp||null,dstIp:form.value.dstIp||null,program:form.value.program||null,accountSids}});rules.value=[...result.rules,...rules.value];message.value=`Saved ${result.created} traffic ignore rule${result.created===1?'':'s'}${result.skipped?` (${result.skipped} already existed)`:''}`;form.value=blank()}catch(cause){error.value=cause.message}finally{busy.value=false}}
function askRemove(rule){cleanupConfirmed.value=false;removeTarget.value=rule}
const removeTarget=ref(null)
async function remove(){if(!removeTarget.value||!cleanupConfirmed.value)return;busy.value=true;error.value='';try{await api(`/settings/traffic-ignores/${removeTarget.value.id}`,{method:'DELETE'});rules.value=rules.value.filter(item=>item.id!==removeTarget.value.id);message.value='Traffic ignore rule removed';removeTarget.value=null}catch(cause){error.value=cause.message}finally{busy.value=false}}
async function cleanup(){if(!cleanupConfirmed.value)return;cleanupBusy.value=true;error.value='';try{const result=await api('/settings/traffic-ignores/cleanup',{method:'POST',body:{confirmed:true}});message.value=`Removed ${result.deleted} stored event${result.deleted===1?'':'s'} matching the active filtering rules`;cleanupOpen.value=false;cleanupConfirmed.value=false}catch(cause){error.value=cause.message}finally{cleanupBusy.value=false}}
onMounted(load)
</script>

<template>
  <section class="traffic-ignores">
    <div class="panel-title"><div><span class="eyebrow">EVENT STORAGE</span><h3>Global traffic ignore rules</h3></div><span class="count-chip">{{rules.length}}</span></div>
    <p class="muted">Ignore matching firewall traffic before it is written to the database. Rules also hide older matching events, including compacted rows, until removed. Enter one or more account SIDs to scope a rule to specific users.</p>
    <form class="traffic-ignore-form" @submit.prevent="create">
      <label>Label<input v-model.trim="form.label" required maxlength="120" placeholder="OpenMonx telemetry"></label>
      <label>Event ID<select v-model.number="form.eventId"><option :value="5150">5150</option><option :value="5151">5151</option><option :value="5156">5156</option><option :value="5157">5157</option></select></label>
      <label>Action<select v-model="form.action"><option value="">Any action</option><option value="allow">Allow</option><option value="block">Block</option></select></label>
      <label>Protocol<select v-model="form.protocol"><option value="">Any protocol</option><option value="TCP">TCP</option><option value="UDP">UDP</option></select></label>
      <label>Direction<select v-model="form.direction"><option value="">Any direction</option><option value="in">Inbound</option><option value="out">Outbound</option></select></label>
      <label>Source IP<input v-model.trim="form.srcIp" placeholder="192.0.2.10"></label>
      <label>Destination IP<input v-model.trim="form.dstIp" placeholder="192.0.2.20"></label>
      <label>Destination port<input v-model.number="form.dstPort" type="number" min="1" max="65535" placeholder="443"></label>
      <label>Program<input v-model.trim="form.program" placeholder="C:\\Program Files\\App\\app.exe"></label>
      <label class="wide-field">User/account SIDs<textarea v-model="form.accountSids" rows="2" spellcheck="false" placeholder="One SID per line, for example S-1-5-21-…"></textarea></label>
      <div class="form-actions"><button class="button primary" :disabled="busy">{{busy?'Saving…':'Add ignore rule'}}</button></div>
    </form>
    <p v-if="message" class="success-msg">{{message}}</p><p v-if="error" class="error-msg">{{error}}</p>
    <div class="cleanup-bar"><div><strong>Retroactive cleanup</strong><span>Delete retained events matching process, traffic, or enabled loopback filters.</span></div><button class="button small danger" :disabled="cleanupBusy" @click="cleanupOpen=true">Review cleanup</button></div>
    <div class="table-wrap"><table><thead><tr><th>LABEL</th><th>TRAFFIC</th><th>PROGRAM</th><th>ACCOUNT</th><th>CREATED</th><th aria-label="Actions"><span class="sr-only">Actions</span></th></tr></thead><tbody><tr v-for="rule in rules" :key="rule.id"><td><strong>{{rule.label}}</strong><small>{{rule.eventId}} · {{rule.action||'any'}}</small></td><td class="mono">{{rule.direction||'any'}} {{rule.protocol||'any'}} {{rule.srcIp||'any'}} → {{rule.dstIp||'any'}}:{{rule.dstPort||'any'}}</td><td class="mono">{{rule.program||'any'}}</td><td class="mono">{{rule.accountSid||'any'}}</td><td>{{rule.createdAt?new Date(rule.createdAt).toLocaleString():'—'}}</td><td><button class="button small danger" :disabled="busy" @click="askRemove(rule)">Remove</button></td></tr><tr v-if="!rules.length"><td colspan="6" class="empty-table">No global traffic ignore rules.</td></tr></tbody></table></div>
  </section>
  <GlassWindow v-model="cleanupOpen" title="Clean up retained events" width="520px"><div class="confirm-dialog"><p>This permanently deletes retained events that match the active process exclusions, traffic ignore rules, or enabled loopback discard setting. New matching events are already discarded at ingestion.</p><label class="check-label"><input v-model="cleanupConfirmed" type="checkbox"> I understand that matching retained events will be permanently deleted.</label><div class="form-actions"><button class="button secondary" @click="cleanupOpen=false;cleanupConfirmed=false">Cancel</button><button class="button danger" :disabled="cleanupBusy||!cleanupConfirmed" @click="cleanup">{{cleanupBusy?'Cleaning…':'Delete matching events'}}</button></div></div></GlassWindow>
  <GlassWindow v-if="removeTarget" :model-value="true" title="Remove traffic ignore rule" width="480px" @update:model-value="value=>{if(!value)removeTarget=null}"><div class="confirm-dialog"><p>Remove <strong>{{removeTarget.label}}</strong>? Matching retained events will become visible and new matches will be stored again.</p><label class="check-label"><input v-model="cleanupConfirmed" type="checkbox"> I understand this rule will stop filtering matching traffic.</label><div class="form-actions"><button class="button secondary" @click="removeTarget=null;cleanupConfirmed=false">Cancel</button><button class="button danger" :disabled="busy||!cleanupConfirmed" @click="remove">{{busy?'Removing…':'Remove rule'}}</button></div></div></GlassWindow>
</template>

<style scoped>
.traffic-ignores{margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)}.traffic-ignores .panel-title{margin-bottom:.5rem}.traffic-ignores h3{margin:0}.traffic-ignore-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin:1rem 0}.traffic-ignore-form label{display:grid;gap:.35rem;font-size:.75rem}.traffic-ignore-form .wide-field{grid-column:span 2}.traffic-ignore-form textarea{min-height:3.6rem;resize:vertical}.traffic-ignore-form .form-actions{align-self:end}.traffic-ignores table{min-width:850px}.traffic-ignores td small{display:block;color:var(--muted);margin-top:.2rem}.traffic-ignores .mono{font-size:.72rem}.cleanup-bar{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin:1rem 0;padding:.8rem 1rem;border:1px solid var(--border);border-radius:6px}.cleanup-bar span{display:block;color:var(--muted);font-size:.8rem;margin-top:.25rem}.confirm-dialog{display:grid;gap:1rem}.confirm-dialog .form-actions{justify-content:flex-end}
</style>
