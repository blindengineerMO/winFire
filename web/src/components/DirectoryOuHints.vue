<script setup>
import {computed} from 'vue'
const props=defineProps({modelValue:{type:Array,default:()=>[]},credentials:{type:Array,default:()=>[]},busy:Boolean})
const emit=defineEmits(['update:modelValue'])
const windowsCredentials=computed(()=>props.credentials.filter(c=>['local','domain'].includes(c.type)))
const update=(index,field,value)=>emit('update:modelValue',props.modelValue.map((hint,i)=>i===index?{...hint,[field]:value}:hint))
const remove=index=>emit('update:modelValue',props.modelValue.filter((_hint,i)=>i!==index))
</script>

<template>
  <fieldset class="ou-hints" :disabled="busy">
    <legend>OU credential preferences</legend>
    <p>Choose a Windows credential for each organizational unit. The closest matching OU also covers its child OUs. Other computers use the default credential above.</p>
    <p class="muted">Explicit node and group credentials take priority. Changes apply on the next AD sync. Existing bindings from older versions are preserved; remove those bindings in Edit node to use an OU preference.</p>
    <div v-for="(hint,index) in modelValue" :key="index" class="ou-hint-row">
      <label>Organizational unit DN<input :value="hint.ouDn" :aria-label="`OU distinguished name ${index+1}`" required maxlength="512" placeholder="OU=Servers,DC=example,DC=com" @input="update(index,'ouDn',$event.target.value)"></label>
      <label>Preferred credential<select :value="hint.credentialId" :aria-label="`OU credential ${index+1}`" required @change="update(index,'credentialId',$event.target.value)"><option value="">Select Windows credential</option><option v-for="credential in windowsCredentials" :key="credential.id" :value="credential.id">{{credential.name}} · {{credential.username}}</option><option v-if="hint.credentialId&&!windowsCredentials.some(c=>c.id===hint.credentialId)" :value="hint.credentialId" disabled>Credential unavailable — select another</option></select></label>
      <button type="button" class="button small danger" :aria-label="`Remove OU mapping ${index+1}`" @click="remove(index)">Remove</button>
    </div>
    <p v-if="!modelValue.length" class="muted">No OU preferences configured.</p>
    <button type="button" class="button small secondary" :disabled="modelValue.length>=200||!windowsCredentials.length" @click="emit('update:modelValue',[...modelValue,{ouDn:'',credentialId:''}])"><i class="mdi mdi-plus"></i> Add OU preference</button>
    <small v-if="!windowsCredentials.length">Add a local or domain credential to the vault first.</small>
  </fieldset>
</template>

<style scoped>
.ou-hints{font-size:.75rem;grid-column:1/-1;min-width:0;margin:0;padding:1rem;border:1px solid var(--border);border-radius:8px}
.ou-hints legend{font-weight:700;padding:0 .4rem;color:var(--field-value)}
.ou-hints p{margin:0 0 .8rem;line-height:1.5}
.ou-hint-row{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr) auto;gap:.8rem;align-items:end;margin-bottom:1rem}
.ou-hint-row label{font-size:.72rem;font-weight:600;display:flex;flex-direction:column;min-width:0;gap:.4rem}
.ou-hint-row input,.ou-hint-row select{width:100%;min-width:0;box-sizing:border-box}
.ou-hints small{display:block;margin-top:.5rem;color:var(--muted)}
@media(max-width:1000px){.ou-hint-row{grid-template-columns:minmax(0,1fr)}.ou-hint-row button{justify-self:start}}
</style>
