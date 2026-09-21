<script setup>
import {onMounted,ref} from 'vue'
import {api} from '../lib/api.js'

const rules=ref([]),busy=ref(false),error=ref(''),message=ref('')
const blank=()=>({label:'',eventId:5157,action:'block',protocol:'TCP',direction:'in',srcIp:'',dstIp:'',dstPort:'',program:'',accountSid:''})
const form=ref(blank())
async function load(){try{rules.value=await api('/settings/traffic-ignores');error.value=''}catch(cause){error.value=cause.message}}
async function create(){busy.value=true;error.value='';message.value='';try{const result=await api('/settings/traffic-ignores',{method:'POST',body:{...form.value,eventId:Number(form.value.eventId),dstPort:form.value.dstPort?Number(form.value.dstPort):null,srcIp:form.value.srcIp||null,dstIp:form.value.dstIp||null,program:form.value.program||null,accountSid:form.value.accountSid||null}});rules.value=[result,...rules.value];message.value='Traffic ignore rule saved';form.value=blank()}catch(cause){error.value=cause.message}finally{busy.value=false}}
async function remove(rule){if(!window.confirm(`Remove the traffic ignore rule “${rule.label}”? Matching events will be visible and new matches will be stored again.`))return;busy.value=true;error.value='';try{await api(`/settings/traffic-ignores/${rule.id}`,{method:'DELETE'});rules.value=rules.value.filter(item=>item.id!==rule.id);message.value='Traffic ignore rule removed'}catch(cause){error.value=cause.message}finally{busy.value=false}}
onMounted(load)
</script>

<template>
  <section class="traffic-ignores">
    <div class="panel-title"><div><span class="eyebrow">EVENT STORAGE</span><h3>Global traffic ignore rules</h3></div><span class="count-chip">{{rules.length}}</span></div>
    <p class="muted">Ignore matching firewall traffic before it is written to the database. Rules also hide older matching events, including compacted rows, until removed.</p>
    <form class="traffic-ignore-form" @submit.prevent="create">
      <label>Label<input v-model.trim="form.label" required maxlength="120" placeholder="OpenMonx telemetry"></label>
      <label>Event ID<select v-model.number="form.eventId"><option :value="5150">5150</option><option :value="5151">5151</option><option :value="5156">5156</option><option :value="5157">5157</option></select></label>
      <label>Action<select v-model="form.action"><option value="allow">Allow</option><option value="block">Block</option></select></label>
      <label>Protocol<select v-model="form.protocol"><option value="TCP">TCP</option><option value="UDP">UDP</option></select></label>
      <label>Direction<select v-model="form.direction"><option value="in">Inbound</option><option value="out">Outbound</option></select></label>
      <label>Source IP<input v-model.trim="form.srcIp" placeholder="192.0.2.10"></label>
      <label>Destination IP<input v-model.trim="form.dstIp" placeholder="192.0.2.20"></label>
      <label>Destination port<input v-model.number="form.dstPort" type="number" min="1" max="65535" placeholder="443"></label>
      <label>Program<input v-model.trim="form.program" placeholder="C:\\Program Files\\App\\app.exe"></label>
      <label>Account SID<input v-model.trim="form.accountSid" placeholder="Optional SID"></label>
      <div class="form-actions"><button class="button primary" :disabled="busy">{{busy?'Saving…':'Add ignore rule'}}</button></div>
    </form>
    <p v-if="message" class="success-msg">{{message}}</p><p v-if="error" class="error-msg">{{error}}</p>
    <div class="table-wrap"><table><thead><tr><th>LABEL</th><th>TRAFFIC</th><th>PROGRAM</th><th>ACCOUNT</th><th>CREATED</th><th></th></tr></thead><tbody><tr v-for="rule in rules" :key="rule.id"><td><strong>{{rule.label}}</strong><small>{{rule.eventId}} · {{rule.action||'any'}}</small></td><td class="mono">{{rule.direction||'any'}} {{rule.protocol||'any'}} {{rule.srcIp||'any'}} → {{rule.dstIp||'any'}}:{{rule.dstPort||'any'}}</td><td class="mono">{{rule.program||'any'}}</td><td class="mono">{{rule.accountSid||'any'}}</td><td>{{rule.createdAt?new Date(rule.createdAt).toLocaleString():'—'}}</td><td><button class="button small danger" :disabled="busy" @click="remove(rule)">Remove</button></td></tr><tr v-if="!rules.length"><td colspan="6" class="empty-table">No global traffic ignore rules.</td></tr></tbody></table></div>
  </section>
</template>

<style scoped>
.traffic-ignores{margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)}.traffic-ignores .panel-title{margin-bottom:.5rem}.traffic-ignores h3{margin:0}.traffic-ignore-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin:1rem 0}.traffic-ignore-form label{display:grid;gap:.35rem;font-size:.75rem}.traffic-ignore-form .form-actions{align-self:end}.traffic-ignores table{min-width:850px}.traffic-ignores td small{display:block;color:var(--muted);margin-top:.2rem}.traffic-ignores .mono{font-size:.72rem}
</style>
