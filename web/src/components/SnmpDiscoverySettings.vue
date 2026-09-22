<script setup>
import {computed,onMounted,ref} from 'vue'
import {api} from '../services/api.js'
const props=defineProps({credentials:{type:Array,default:()=>[]}})
const targets=ref([]),busy=ref(false),error=ref(''),message=ref('')
const form=ref({name:'',host:'',cidr:'',credentialId:'',pollIntervalMinutes:60,enabled:true})
const snmpCredentials=computed(()=>props.credentials.filter(item=>['snmp-v2c','snmp-v3'].includes(item.type)))
async function load(){try{targets.value=await api('/discovery/snmp-targets');error.value=''}catch(e){error.value=e.message}}
async function save(){busy.value=true;error.value='';message.value='';try{await api('/discovery/snmp-targets',{method:'POST',body:{...form.value,pollIntervalMinutes:Number(form.value.pollIntervalMinutes),cidr:form.value.cidr||undefined}});form.value={name:'',host:'',cidr:'',credentialId:snmpCredentials.value[0]?.id||'',pollIntervalMinutes:60,enabled:true};message.value='SNMP discovery target saved';await load()}catch(e){error.value=e.message}finally{busy.value=false}}
async function poll(target){busy.value=true;error.value='';message.value='';try{const result=await api(`/discovery/snmp-targets/${target.id}/poll`,{method:'POST',body:{}});message.value=`Polled ${target.name}: ${result.arpCount} ARP entries, ${result.macPortCount} MAC ports`;await load()}catch(e){error.value=e.message}finally{busy.value=false}}
async function remove(target){if(!window.confirm(`Remove SNMP target ${target.name}?`))return;busy.value=true;try{await api(`/discovery/snmp-targets/${target.id}`,{method:'DELETE'});await load()}catch(e){error.value=e.message}finally{busy.value=false}}
onMounted(async()=>{await load();form.value.credentialId=snmpCredentials.value[0]?.id||''})
</script>
<template>
  <section class="snmp-settings">
    <div class="panel-title"><div><span class="eyebrow">NETWORK DISCOVERY</span><h2>SNMP switch and router polling</h2></div><span class="count-chip">{{targets.length}} targets</span></div>
    <p class="muted">Use a read-only SNMP v2c community or SNMP v3 account to collect switch/router ARP caches and forwarding tables. ARP IPs inside the optional CIDR are registered as discovery candidates and follow the normal DNS and management verification flow.</p>
    <form class="form-grid" @submit.prevent="save">
      <label>Target name<input v-model.trim="form.name" required placeholder="Core switch"></label>
      <label>Switch/router host<input v-model.trim="form.host" required placeholder="10.20.0.1"></label>
      <label>Candidate scope CIDR (optional)<input v-model.trim="form.cidr" placeholder="10.20.0.0/24"></label>
      <label>SNMP credential<select v-model="form.credentialId" required><option value="">Select SNMP credential</option><option v-for="credential in snmpCredentials" :key="credential.id" :value="credential.id">{{credential.name}} · {{credential.type}}</option></select></label>
      <label>Poll interval (minutes)<input v-model.number="form.pollIntervalMinutes" type="number" min="5" max="10080" required></label>
      <label class="check-label"><input v-model="form.enabled" type="checkbox"> Enable scheduled polling</label>
      <div class="form-actions"><button class="button primary" :disabled="busy||!snmpCredentials.length">{{busy?'Saving…':'Add SNMP target'}}</button></div>
    </form>
    <p v-if="!snmpCredentials.length" class="hint">Create an SNMP v2c or SNMP v3 entry in Administration → Credentials first. Secrets are encrypted and never returned.</p>
    <div v-if="error" class="error-msg">{{error}}</div><div v-if="message" class="success-msg">{{message}}</div>
    <div class="table-wrap"><table><thead><tr><th>TARGET</th><th>HOST</th><th>SCOPE</th><th>CREDENTIAL</th><th>LAST POLL</th><th>RESULT</th><th>ACTIONS</th></tr></thead><tbody>
      <tr v-for="target in targets" :key="target.id"><td><strong>{{target.name}}</strong><small>{{target.enabled?'Scheduled':'Paused'}} · every {{target.pollIntervalMinutes}}m</small></td><td class="mono">{{target.host}}</td><td class="mono">{{target.cidr||'All ARP entries'}}</td><td>{{target.credentialName}}</td><td>{{target.lastPollAt?new Date(target.lastPollAt).toLocaleString():'Never'}}</td><td><span class="status" :class="target.lastStatus==='complete'?'reachable':target.lastStatus==='failed'?'unreachable':'unknown'">{{target.lastStatus||'Pending'}}</span><small v-if="target.lastStatus==='complete'">{{target.arpCount}} ARP · {{target.macPortCount}} MAC ports · {{target.registeredCount}} registered</small><small v-if="target.lastError" class="danger-text">{{target.lastError}}</small></td><td><div class="inline-actions"><button class="button small secondary" :disabled="busy" @click="poll(target)">Poll now</button><button class="button small danger" :disabled="busy" @click="remove(target)">Remove</button></div></td></tr>
      <tr v-if="!targets.length"><td colspan="7" class="empty-table">No SNMP discovery targets configured.</td></tr>
    </tbody></table></div>
  </section>
</template>
<style scoped>.snmp-settings{display:grid;gap:1rem}.snmp-settings .muted,.snmp-settings .hint{padding:0 1rem}.snmp-settings .form-grid{padding:0 1rem}.snmp-settings td small{display:block;color:var(--muted);font-size:.7rem;margin-top:.25rem}.snmp-settings .danger-text{color:var(--danger)}</style>
