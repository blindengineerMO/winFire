<script setup>
import {computed,onMounted,ref,watch} from 'vue'
import {api} from '../lib/api.js'

const resources=ref([]),users=ref([]),grants=ref([]),resourceKey=ref(''),userId=ref(''),permission=ref('read'),busy=ref(false),error=ref(''),message=ref('')
const selected=computed(()=>resources.value.find(item=>`${item.type}:${item.id}`===resourceKey.value))
const selectedUser=computed(()=>users.value.find(item=>item.id===userId.value))
async function load(){
  try{
    const [availableResources,availableUsers]=await Promise.all([api('/access/resources'),api('/access/users')])
    resources.value=availableResources
    users.value=availableUsers
    if(!resources.value.some(item=>`${item.type}:${item.id}`===resourceKey.value))resourceKey.value=resources.value.length?`${resources.value[0].type}:${resources.value[0].id}`:''
    if(!users.value.some(item=>item.id===userId.value))userId.value=users.value[0]?.id||''
    error.value=''
  }catch(e){error.value=e.message}
}
async function loadGrants(){
  grants.value=[]
  if(!selected.value)return
  try{grants.value=await api(`/access/grants?type=${encodeURIComponent(selected.value.type)}&resourceId=${encodeURIComponent(selected.value.id)}`)}catch(e){error.value=e.message}
}
async function saveGrant(){
  if(!selected.value||!userId.value)return
  busy.value=true;error.value='';message.value=''
  try{
    await api('/access/grants',{method:'POST',body:{type:selected.value.type,resourceId:selected.value.id,userId:userId.value,permission:permission.value}})
    await loadGrants()
    message.value=`Access saved for ${selectedUser.value?.email||'user'}`
  }catch(e){error.value=e.message}finally{busy.value=false}
}
async function revokeGrant(grant){
  busy.value=true;error.value='';message.value=''
  try{await api(`/access/grants/${grant.id}`,{method:'DELETE'});await loadGrants();message.value=`Access removed for ${grant.email}`}
  catch(e){error.value=e.message}finally{busy.value=false}
}
watch(resourceKey,loadGrants)
onMounted(load)
</script>

<template>
  <div class="panel-title"><div><span class="eyebrow">RESOURCE ACCESS</span><h2>Policy, group and credential grants</h2></div></div>
  <div class="resource-grants">
    <p>Give another operator read or write access to a resource you manage. Write access lets policy editors change it. Auditors can receive read access only.</p>
    <p v-if="error" class="error-msg">{{error}}</p><p v-if="message" class="success-msg">{{message}}</p>
    <div v-if="!resources.length" class="empty-side">Create a policy, node group or credential to share it.</div>
    <template v-else>
      <label>Resource<select v-model="resourceKey"><option v-for="item in resources" :key="`${item.type}:${item.id}`" :value="`${item.type}:${item.id}`">{{item.type.replace('_',' ')}} · {{item.name}}</option></select></label>
      <form class="grant-form" @submit.prevent="saveGrant">
        <label>Operator<select v-model="userId" required><option value="">Select operator</option><option v-for="user in users" :key="user.id" :value="user.id">{{user.email}} · {{user.role}}</option></select></label>
        <label>Access<select v-model="permission"><option value="read">Read</option><option value="write" :disabled="selectedUser?.role==='auditor'">Write</option></select></label>
        <button class="button primary" :disabled="busy||!userId||selectedUser?.role==='auditor'&&permission==='write'">Save access</button>
      </form>
      <div class="table-wrap"><table><thead><tr><th>OPERATOR</th><th>ACCESS</th><th>ACTIONS</th></tr></thead><tbody><tr v-for="grant in grants" :key="grant.id"><td>{{grant.email}}</td><td><span class="status">{{grant.permission}}</span></td><td><button class="button small danger" :disabled="busy" @click="revokeGrant(grant)">Remove</button></td></tr><tr v-if="!grants.length"><td colspan="3" class="empty-table">No direct grants for this resource.</td></tr></tbody></table></div>
    </template>
  </div>
</template>
