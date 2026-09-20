<script setup>
import {computed,onMounted,ref} from 'vue'
import PageHeader from '../components/PageHeader.vue'
import GlassWindow from '../components/GlassWindow.vue'
import {api,session} from '../lib/api.js'

const items=ref([]),total=ref(0),page=ref(1),pageSize=ref(50),sortBy=ref('name'),sortDir=ref('asc')
const query=ref(''),enabled=ref('all'),mfa=ref('all'),loading=ref(false),busy=ref(false),error=ref(''),message=ref('')
const detail=ref(null),detailOpen=ref(false),role=ref('auditor')
const isAdmin=computed(()=>['owner','admin'].includes(session.user?.role))
const pages=computed(()=>Math.max(1,Math.ceil(total.value/pageSize.value)))
async function load(){
  loading.value=true;error.value=''
  try{
    const params=new URLSearchParams({q:query.value,enabled:enabled.value,mfa:mfa.value,page:String(page.value),pageSize:String(pageSize.value),sortBy:sortBy.value,sortDir:sortDir.value})
    const result=await api(`/directory/users?${params}`);items.value=result.items;total.value=result.total
  }catch(cause){error.value=cause.message}finally{loading.value=false}
}
function search(){page.value=1;load()}
function sort(column){if(sortBy.value===column)sortDir.value=sortDir.value==='asc'?'desc':'asc';else{sortBy.value=column;sortDir.value='asc'};search()}
async function openDetail(user){try{detail.value=await api(`/directory/users/${user.id}`);role.value='auditor';detailOpen.value=true}catch(cause){error.value=cause.message}}
async function sync(){busy.value=true;error.value='';try{const result=await api('/directory/sync',{method:'POST',body:{}});message.value=`Synced ${result.users?.count??0} directory users${result.userSyncError?`; user sync failed: ${result.userSyncError}`:''}`;await load()}catch(cause){error.value=cause.message}finally{busy.value=false}}
async function importOperator(){if(!detail.value)return;busy.value=true;error.value='';try{await api(`/directory/users/${detail.value.id}/import-operator`,{method:'POST',body:{role:role.value}});message.value=`${detail.value.display_name} can sign in with AD credentials`;detail.value=await api(`/directory/users/${detail.value.id}`);await load()}catch(cause){error.value=cause.message}finally{busy.value=false}}
onMounted(load)
</script>

<template>
  <div class="view directory-view">
    <PageHeader eyebrow="ENTITIES / ACTIVE DIRECTORY" title="Directory" description="Search AD users, enrollment status and access activity"><button v-if="isAdmin" class="button small secondary" :disabled="busy" @click="sync"><i class="mdi mdi-sync"></i> {{busy?'Syncing…':'Sync directory'}}</button></PageHeader>
    <p v-if="error" class="error-msg" role="alert">{{error}}</p><p v-if="message" class="success-msg">{{message}}</p>
    <section class="panel glass directory-panel">
      <div class="panel-title"><h2>AD user inventory</h2><span class="count-chip">{{total}} users</span></div>
      <form class="directory-filters" @submit.prevent="search">
        <label>Search<input v-model.trim="query" placeholder="Name, username, email or UPN"></label>
        <label>Account<select v-model="enabled" @change="search"><option value="all">All</option><option value="true">Enabled</option><option value="false">Disabled</option></select></label>
        <label>Authenticator<select v-model="mfa" @change="search"><option value="all">All</option><option value="enrolled">Enrolled</option><option value="missing">Not enrolled</option></select></label>
        <label>Rows<select v-model.number="pageSize" @change="search"><option :value="25">25</option><option :value="50">50</option><option :value="100">100</option><option :value="250">250</option></select></label>
        <button class="button small primary" :disabled="loading">Search</button>
      </form>
      <div class="table-wrap"><table><thead><tr><th><button @click="sort('name')">NAME ↕</button></th><th><button @click="sort('username')">USERNAME ↕</button></th><th><button @click="sort('email')">EMAIL ↕</button></th><th><button @click="sort('status')">ACCOUNT ↕</button></th><th>MFA</th><th>OPERATOR</th><th><button @click="sort('lastLogon')">LAST LOGON ↕</button></th></tr></thead><tbody><tr v-for="user in items" :key="user.id" class="directory-row" @click="openDetail(user)"><td><strong>{{user.display_name}}</strong></td><td class="mono">{{user.sam_account_name||'—'}}</td><td>{{user.email||user.upn||'—'}}</td><td><span class="status" :class="user.missing||!user.enabled?'unreachable':'reachable'">{{user.missing?'Missing':user.enabled?'Enabled':'Disabled'}}</span></td><td>{{user.mfa_enrolled?'Enrolled':'—'}}</td><td>{{user.operator_imported?'Imported':'—'}}</td><td>{{user.last_logon_at?new Date(user.last_logon_at).toLocaleString():'—'}}</td></tr><tr v-if="!items.length"><td colspan="7" class="empty-table">{{loading?'Loading users…':'No directory users match these filters. Run a directory sync if this is the first visit.'}}</td></tr></tbody></table></div>
      <div class="directory-pagination"><span>Page {{page}} of {{pages}}</span><div><button class="button small secondary" :disabled="page<=1||loading" @click="page--;load()">Previous</button><button class="button small secondary" :disabled="page>=pages||loading" @click="page++;load()">Next</button></div></div>
    </section>
    <GlassWindow v-model="detailOpen" :title="detail?.display_name||'Directory user'" width="760px"><div v-if="detail" class="directory-detail">
      <div class="directory-facts"><div><small>AD USERNAME</small><strong>{{detail.sam_account_name||'—'}}</strong></div><div><small>UPN</small><strong>{{detail.upn||'—'}}</strong></div><div><small>SID</small><strong>{{detail.sid}}</strong></div><div><small>ACCOUNT</small><strong>{{detail.missing?'Missing':detail.enabled?'Enabled':'Disabled'}}</strong></div><div><small>AUTHENTICATOR</small><strong>{{detail.mfaEnrolled?'Enrolled':'Not enrolled'}}</strong></div><div><small>OPERATOR</small><strong>{{detail.operatorImported?'Imported':'Not imported'}}</strong></div></div>
      <p class="muted directory-dn">{{detail.dn}}</p>
      <div v-if="isAdmin" class="directory-import"><label>Import as operator<select v-model="role"><option value="auditor">Auditor</option><option value="editor">Policy editor</option><option value="admin">Administrator</option></select></label><button class="button small primary" :disabled="busy||!detail.enabled||detail.missing" @click="importOperator">{{detail.operatorImported?'Update role':'Import operator'}}</button></div>
      <h3>MFA events</h3><p v-if="!detail.mfaEvents?.length" class="muted">No MFA events recorded.</p><div v-for="event in detail.mfaEvents" :key="event.id" class="directory-event"><span>{{new Date(event.challenged_at).toLocaleString()}}</span><strong>{{event.status}}</strong><span>{{event.node_id||'—'}}</span></div>
      <h3>Windows logon events</h3><p v-if="!detail.logonEvents?.length" class="muted">No matching Security logon events recorded.</p><div v-for="event in detail.logonEvents" :key="event.id" class="directory-event"><span>{{new Date(event.event_time).toLocaleString()}}</span><strong>{{event.event_id===4624?'Logon':event.event_id===4625?'Failed logon':'Logoff'}}</strong><span>{{event.hostname||event.node_id}} · {{event.src_ip||'—'}}</span></div>
    </div></GlassWindow>
  </div>
</template>

<style scoped>
.directory-panel{min-width:0}.directory-filters{display:flex;align-items:end;gap:.7rem;flex-wrap:wrap;padding:1rem}.directory-filters label{display:grid;gap:.3rem;min-width:120px;font-size:.75rem}.directory-filters label:first-child{flex:1 1 250px}.directory-filters input,.directory-filters select{width:100%;min-width:0}.directory-panel th button{border:0;background:none;color:inherit;font:inherit;font-weight:700;cursor:pointer;padding:0}.directory-row{cursor:pointer}.directory-row:hover{background:color-mix(in srgb,var(--cyan) 9%,transparent)}.directory-pagination{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:1rem}.directory-pagination div{display:flex;gap:.5rem}.directory-detail{display:grid;gap:.8rem;min-width:0}.directory-detail h3{margin:.65rem 0 0}.directory-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:.5rem}.directory-facts>div{display:grid;gap:.25rem;padding:.7rem;border:1px solid var(--border);border-radius:7px;min-width:0}.directory-facts small{font-size:.66rem;letter-spacing:.08em;color:var(--muted)}.directory-facts strong,.directory-dn{overflow-wrap:anywhere}.directory-import{display:flex;align-items:end;gap:.6rem;flex-wrap:wrap;padding:.7rem;border:1px solid var(--border);border-radius:7px}.directory-import label{display:grid;gap:.3rem;min-width:180px}.directory-event{display:grid;grid-template-columns:155px 110px minmax(0,1fr);gap:.5rem;padding:.4rem .2rem;border-bottom:1px solid var(--border);font-size:.78rem}.directory-event span{overflow-wrap:anywhere}@media(max-width:600px){.directory-pagination,.directory-event{display:flex;flex-wrap:wrap}.directory-filters{padding:.7rem}}
</style>
