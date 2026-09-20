<script setup>
import {onMounted,ref} from 'vue'
import {api} from '../lib/api.js'

const destinations=ref([]),error=ref(''),message=ref(''),busy=ref(false)
const form=ref({id:'',name:'',kind:'syslog_tls',endpoint:'',token:''})
async function load(){try{destinations.value=await api('/event-export/destinations')}catch(cause){error.value=cause.message}}
function edit(destination){form.value={id:destination.id,name:destination.name,kind:destination.kind,endpoint:destination.endpoint,token:''};error.value='';message.value=''}
function reset(){form.value={id:'',name:'',kind:'syslog_tls',endpoint:'',token:''}}
async function save(){busy.value=true;error.value='';message.value='';try{
  const {id,...fields}=form.value
  await api(id?`/event-export/destinations/${id}`:'/event-export/destinations',{method:id?'PATCH':'POST',body:{...fields,...(!fields.token?{token:undefined}:{})}})
  message.value=id?'Destination updated':'Destination added';reset();await load()
}catch(cause){error.value=cause.message}finally{busy.value=false}}
async function remove(destination){if(!window.confirm(`Delete ${destination.name} as an event export destination?`))return;busy.value=true;error.value='';try{await api(`/event-export/destinations/${destination.id}`,{method:'DELETE'});message.value='Destination deleted';if(form.value.id===destination.id)reset();await load()}catch(cause){error.value=cause.message}finally{busy.value=false}}
onMounted(load)
</script>

<template>
  <section class="export-settings">
    <h3>External event export</h3>
    <p class="muted">Send only the events selected in Firewall events to a trusted syslog TLS server or Splunk HEC endpoint. WinFire retains the original events.</p>
    <p v-if="error" class="error-msg" role="alert">{{error}}</p><p v-if="message" class="success-msg">{{message}}</p>
    <div v-for="destination in destinations" :key="destination.id" class="export-destination"><div><strong>{{destination.name}}</strong><small>{{destination.kind==='splunk_hec'?'Splunk HEC':'Syslog TLS'}} · {{destination.endpoint}}</small></div><button class="button small secondary" :disabled="busy" @click="edit(destination)">Edit</button><button class="button small danger" :disabled="busy" @click="remove(destination)">Delete</button></div>
    <form class="export-form" @submit.prevent="save">
      <h4>{{form.id?'Edit destination':'Add destination'}}</h4>
      <label>Name<input v-model.trim="form.name" required maxlength="100" placeholder="Security operations"></label>
      <label>Type<select v-model="form.kind"><option value="syslog_tls">Syslog over TLS</option><option value="splunk_hec">Splunk HEC</option></select></label>
      <label>Endpoint<input v-model.trim="form.endpoint" required :placeholder="form.kind==='syslog_tls'?'logs.example.com:6514':'https://splunk.example.com:8088/services/collector/event'"></label>
      <label v-if="form.kind==='splunk_hec'">HEC token<input v-model="form.token" type="password" :required="!form.id" autocomplete="new-password" :placeholder="form.id?'Leave blank to keep current token':''"><small>Stored encrypted; never displayed again.</small></label>
      <div class="export-actions"><button class="button small primary" :disabled="busy">{{busy?'Saving…':'Save destination'}}</button><button v-if="form.id" type="button" class="button small secondary" @click="reset">Cancel edit</button></div>
    </form>
  </section>
</template>

<style scoped>
.export-settings{border-top:1px solid var(--border);padding:1.2rem 0;display:grid;gap:.65rem}.export-settings h3,.export-form h4{margin:0}.export-settings p{margin:.2rem 0}.export-destination{display:flex;align-items:center;gap:.5rem;padding:.6rem;border:1px solid var(--border);border-radius:7px}.export-destination div{display:grid;gap:.2rem;min-width:0;flex:1}.export-destination small{overflow-wrap:anywhere;color:var(--muted)}.export-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.7rem;padding:.9rem;border:1px solid var(--border);border-radius:7px}.export-form h4,.export-actions{grid-column:1/-1}.export-form label{display:grid;gap:.3rem;font-size:.75rem}.export-form small{color:var(--muted)}.export-actions{display:flex;gap:.5rem;flex-wrap:wrap}
</style>
