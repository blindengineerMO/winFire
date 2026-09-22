<script setup>
import {onMounted,ref} from 'vue'
import {api} from '../services/api.js'
import TrafficIgnores from './TrafficIgnores.vue'

const names=ref('')
const busy=ref(false)
const error=ref('')
const message=ref('')
const describeError=cause=>cause.message==='Not Found'?'The running API does not have process exclusions yet. Restart WinFire, then reload this page.':cause.message

onMounted(async()=>{
  try{names.value=(await api('/settings/process-exclusions')).names.join('\n')}
  catch(e){error.value=describeError(e)}
})

async function save(){
  busy.value=true;error.value='';message.value=''
  try{
    const list=names.value.split(/[\n,]+/).map(name=>name.trim()).filter(Boolean)
    const result=await api('/settings/process-exclusions',{method:'PUT',body:{names:list}})
    names.value=result.names.join('\n')
    message.value=`Saved ${result.names.length} global process exclusion${result.names.length===1?'':'s'}`
  }catch(e){error.value=describeError(e)}
  finally{busy.value=false}
}
</script>

<template>
  <div class="process-exclusions">
    <h3>Global process exclusions</h3>
    <p>Enter one executable name per line, such as <code>openmonx-agent.exe</code>. Matching is case insensitive and uses the file name at the end of a Windows path. New matching firewall events are discarded before storage; older matching events disappear from Activities and search. Existing records remain until normal retention removes them.</p>
    <form @submit.prevent="save">
      <label>Executable names
        <textarea v-model="names" rows="5" spellcheck="false" placeholder="openmonx-agent.exe" aria-label="Excluded executable names"></textarea>
      </label>
      <button class="button primary" :disabled="busy">{{busy?'Saving…':'Save exclusions'}}</button>
    </form>
    <p v-if="error" class="error-msg">{{error}}</p>
    <p v-if="message" class="success-msg">{{message}}</p>
  </div>
  <TrafficIgnores />
</template>

<style scoped>
.process-exclusions{margin-top:2rem;padding-top:1.5rem;border-top:1px solid var(--border)}
.process-exclusions form{display:grid;gap:1rem;max-width:640px}
.process-exclusions label{display:grid;gap:.5rem;font-weight:600}
.process-exclusions textarea{width:100%;min-height:8rem;padding:.75rem;background:var(--panel);color:inherit;border:1px solid var(--border);border-radius:4px;font:inherit;resize:vertical}
.process-exclusions button{justify-self:start}
</style>
