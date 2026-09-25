<script setup>
import {ref,computed,onMounted,onUnmounted,watch} from 'vue'
import {api,session} from '../services/api.js'
import GlassWindow from './GlassWindow.vue'
const options=ref({users:[],canAdminister:false,mcpUrl:null}),page=ref({items:[],total:0}),query=ref({q:'',owner:'self',status:'all',purpose:'all',sort:'created',direction:'desc',page:1,pageSize:25})
const optionsLoading=ref(false),optionsError=ref(''),listError=ref('')
const pageError=computed(()=>optionsError.value||listError.value||error.value)
const loading=ref(false),busy=ref(false),error=ref(''),notice=ref(''),dialog=ref(''),selected=ref(null),secret=ref(''),copied=ref(false),form=ref({}),nodes=ref([]),nodeSearch=ref(''),pendingAction=ref('')
const toLocal=value=>{const d=new Date(value);return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16)}
const when=value=>value?new Date(value).toLocaleString():'Never'
const title=computed(()=>({create:'Create API key',edit:'Edit API key',secret:'Save your new key',confirm:pendingAction.value==='delete'?'Delete API key':pendingAction.value==='revoke'?'Revoke API key':'Rotate API key'})[dialog.value]||'API key')
let revision=0,optionsRevision=0
const loadError=(e,subject)=>e.status===404
  ?'API key management is unavailable on this server. Make sure the API server has been updated and restarted, then select Refresh.'
  :`Could not load ${subject}: ${e.message}`
async function load(){const current=++revision;loading.value=true;try{const result=await api('/api-keys?'+new URLSearchParams(query.value));if(current===revision){page.value=result;listError.value=''}}catch(e){if(current===revision)listError.value=loadError(e,'API keys')}finally{if(current===revision)loading.value=false}}
async function loadOptions(){const current=++optionsRevision;optionsLoading.value=true;try{const result=await api('/api-keys/options');if(current===optionsRevision){options.value=result;optionsError.value=''}}catch(e){if(current===optionsRevision)optionsError.value=loadError(e,'key-management options')}finally{if(current===optionsRevision)optionsLoading.value=false}}
async function refresh(){await Promise.all([loadOptions(),load()])}
function search(){query.value.page=1;load()}
function sort(key){query.value.direction=query.value.sort===key&&query.value.direction==='asc'?'desc':'asc';query.value.sort=key;search()}
function create(){error.value='';form.value={name:'',userId:session.user.id,purpose:'api',allowWrites:false,expires:toLocal(Date.now()+90*86400000),nodeId:''};nodeSearch.value='';nodes.value=[];dialog.value='create'}
function edit(key){error.value='';selected.value=key;form.value={name:key.name,expires:toLocal(key.expiresAt)};dialog.value='edit'}
async function findNodes(){try{nodes.value=(await api('/nodes?page=1&pageSize=100&search='+encodeURIComponent(nodeSearch.value)+'&sort=hostname')).items}catch(e){error.value=e.message}}
function purposeChanged(){form.value.allowWrites=false;form.value.nodeId='';if(form.value.purpose==='mcp'&&options.value.canAdminister)findNodes()}
async function act(fn){if(busy.value)return;busy.value=true;error.value='';notice.value='';try{await fn();await load()}catch(e){error.value=e.message}finally{busy.value=false}}
function showSecret(result){selected.value=result.key;secret.value=result.secret;copied.value=false;dialog.value='secret'}
async function save(){await act(async()=>{
  const expiresAt=new Date(form.value.expires).toISOString()
  if(dialog.value==='create')showSecret(await api('/api-keys',{method:'POST',body:{name:form.value.name,userId:form.value.userId,purpose:form.value.purpose,access:form.value.allowWrites?'write':'read',expiresAt,nodeIds:form.value.purpose==='mcp'&&form.value.nodeId?[form.value.nodeId]:[]}}))
  else{await api('/api-keys/'+selected.value.id,{method:'PATCH',body:{name:form.value.name,expiresAt}});dialog.value='';notice.value='Key details updated.'}
})}
function confirm(key,action){selected.value=key;pendingAction.value=action;error.value='';dialog.value='confirm'}
async function perform(){await act(async()=>{
  const action=pendingAction.value,result=await api('/api-keys/'+selected.value.id+(action==='delete'?'':'/'+action),{method:action==='delete'?'DELETE':'POST'})
  if(action==='rotate')showSecret(result)
  else{dialog.value='';notice.value=action==='delete'?'API key deleted. Historical audit and usage records are retained.':'API key revoked.'}
})}
async function copy(){try{await navigator.clipboard.writeText(secret.value);copied.value=true}catch{error.value='Select the key and copy it manually.'}}
watch(dialog,value=>{if(value!=='secret'){secret.value='';copied.value=false}})
onMounted(refresh)
onUnmounted(()=>{revision++;optionsRevision++;secret.value=''})
</script>
<template>
  <section class="user-api-keys">
    <div class="panel-title"><h2>User API keys</h2><button class="button primary" :disabled="busy||optionsLoading||!!optionsError||!options.users.length" @click="create"><i class="mdi mdi-plus"></i> Create API key</button></div>
    <p class="muted">Create keys for API automation or MCP AI usage reporting. API permissions follow the key owner’s current role. Key secrets are shown once.</p>
    <p v-if="pageError&&!dialog" class="error-msg" role="alert">{{pageError}}</p><p v-if="notice" class="success-msg" role="status">{{notice}}</p>
    <form class="key-toolbar" @submit.prevent="search">
      <input v-model="query.q" aria-label="Search API keys" placeholder="Search key name, prefix or owner">
      <select v-if="options.canAdminister" v-model="query.owner" aria-label="Key owner filter" @change="search"><option value="self">My keys</option><option value="all">All permitted users</option><option v-for="user in options.users" :key="user.id" :value="user.id">{{user.email}}</option></select>
      <select v-model="query.purpose" aria-label="Key purpose filter" @change="search"><option value="all">API and MCP</option><option value="api">API</option><option value="mcp">MCP</option></select>
      <select v-model="query.status" aria-label="Key status filter" @change="search"><option value="all">All states</option><option value="active">Active</option><option value="expired">Expired</option><option value="revoked">Revoked</option></select>
      <button class="button secondary" :disabled="loading">Search</button><button type="button" class="button secondary" :disabled="loading||optionsLoading" @click="refresh">Refresh</button>
    </form>
    <div class="table-wrap"><table><thead><tr><th><button class="sort" @click="sort('name')">Key ↕</button></th><th>Owner</th><th>Access</th><th>Status</th><th><button class="sort" @click="sort('expires')">Expires ↕</button></th><th><button class="sort" @click="sort('used')">Last used ↕</button></th><th>Actions</th></tr></thead><tbody>
      <tr v-for="key in page.items" :key="key.id"><td><strong>{{key.name}}</strong><small>{{key.prefix}}…</small></td><td>{{key.ownerEmail}}</td><td>{{key.purpose==='mcp'?'MCP · AI reporting':key.scopes.includes('api:write')?'API · Read and write':'API · Read only'}}<small v-if="key.purpose==='mcp'">{{key.nodeIds.length?key.nodeIds.length+' reporting node(s)':'Unmapped user reports'}}</small></td><td><span :class="['status',key.status==='active'?'reachable':'unknown']">{{key.status}}</span></td><td>{{when(key.expiresAt)}}</td><td>{{when(key.lastUsedAt)}}</td><td><div class="key-actions"><button class="button small secondary" @click="edit(key)">Edit</button><button class="button small secondary" :disabled="key.status!=='active'" @click="confirm(key,'rotate')">Rotate</button><button class="button small secondary" :disabled="key.status==='revoked'" @click="confirm(key,'revoke')">Revoke</button><button class="button small danger" @click="confirm(key,'delete')">Delete</button></div></td></tr>
      <tr v-if="!page.items.length"><td colspan="7">{{loading?'Loading keys…':listError?'API keys could not be loaded. Select Refresh to retry.':'No keys match these filters.'}}</td></tr>
    </tbody></table></div>
    <div class="key-toolbar"><span>{{page.total}} keys · page {{query.page}}</span><label>Rows<select v-model.number="query.pageSize" @change="search"><option :value="25">25</option><option :value="50">50</option><option :value="100">100</option></select></label><button class="button secondary" :disabled="loading||query.page===1" @click="query.page--;load()">Previous</button><button class="button secondary" :disabled="loading||query.page*query.pageSize>=page.total" @click="query.page++;load()">Next</button></div>
    <GlassWindow :model-value="!!dialog" :title="title" width="680px" @update:model-value="open=>{if(!open&&!busy)dialog=''}">
      <p v-if="error" class="error-msg" role="alert">{{error}}</p>
      <form v-if="dialog==='create'||dialog==='edit'" class="key-form" @submit.prevent="save">
        <label>Key name<input v-model.trim="form.name" required maxlength="100" placeholder="Inventory integration"></label>
        <label>Expires<input v-model="form.expires" type="datetime-local" required><small>Up to one year; default is 90 days.</small></label>
        <template v-if="dialog==='create'">
          <label v-if="options.canAdminister">Key owner<select v-model="form.userId" required><option v-for="user in options.users" :key="user.id" :value="user.id">{{user.email}}</option></select></label>
          <label>Purpose<select v-model="form.purpose" @change="purposeChanged"><option value="api">WinFire API</option><option value="mcp">MCP AI usage reporting</option></select></label>
          <label v-if="form.purpose==='api'" class="switch-field wide"><span>Allow API writes</span><input v-model="form.allowWrites" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label>
          <p v-if="form.purpose==='api'" class="muted wide">Read access uses GET/HEAD requests. Writes remain limited by the owner’s permissions. Keys cannot administer other API keys.</p>
          <template v-if="form.purpose==='mcp'">
            <p class="muted wide">This key can call report_ai_usage and report_ai_usage_batch. It cannot read or administer the WinFire API. Reports are attributed to the key owner.</p>
            <div v-if="options.canAdminister" class="wide"><label>Find reporting node<input v-model="nodeSearch" placeholder="Hostname or address" @keydown.enter.prevent="findNodes"></label><button type="button" class="button small secondary" @click="findNodes">Find nodes</button><label>Reporting node<select v-model="form.nodeId"><option value="">None — keep reports unmapped</option><option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}} · {{node.ip}}</option></select></label><small>Search returns up to 100 matches. Administrators can bind a key to a specific node.</small></div>
            <p v-else class="muted wide">Reports remain unmapped. An administrator can create a node-bound key for your account.</p>
          </template>
        </template>
        <p v-else class="muted wide">Owner, purpose and node binding are fixed. Create a replacement key to change them. Updating expiry does not reactivate a revoked key.</p>
        <div class="form-actions wide"><button type="button" class="button secondary" :disabled="busy" @click="dialog=''">Cancel</button><button class="button primary" :disabled="busy">{{busy?'Saving…':dialog==='create'?'Create key':'Save changes'}}</button></div>
      </form>
      <template v-if="dialog==='secret'"><p>Copy this key now. It cannot be retrieved after closing this dialog.</p><label class="key-secret">New API key<textarea :value="secret" readonly rows="3" spellcheck="false" autocomplete="off"></textarea></label><button class="button secondary" @click="copy">{{copied?'Copied':'Copy key'}}</button><p>Send the key using <code>Authorization: Bearer &lt;key&gt;</code>.</p><p v-if="selected?.purpose==='mcp'">MCP endpoint: <code class="endpoint">{{options.mcpUrl||'Configure the server public URL in Server config.'}}</code></p><p v-else>API base: <code>/api/v1</code></p><div class="form-actions"><button class="button primary" @click="dialog=''">Done</button></div></template>
      <template v-if="dialog==='confirm'"><p>{{pendingAction==='rotate'?'Rotating invalidates the old key immediately. Update its clients with the replacement key.':pendingAction==='revoke'?'Revoking immediately prevents this key from authenticating.':'Deleting immediately invalidates this key and removes its entry. Audit and AI usage history are retained.'}}</p><p><strong>{{selected?.name}}</strong> · {{selected?.ownerEmail}}</p><div class="form-actions"><button class="button secondary" :disabled="busy" @click="dialog=''">Cancel</button><button :class="['button',pendingAction==='rotate'?'primary':'danger']" :disabled="busy" @click="perform">{{pendingAction==='rotate'?'Rotate key':pendingAction==='revoke'?'Revoke key':'Delete key'}}</button></div></template>
    </GlassWindow>
  </section>
</template>
<style scoped>
.user-api-keys{min-width:0}.key-toolbar,.key-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.key-toolbar{margin:16px 0}.key-toolbar>input{flex:1;min-width:180px}.key-toolbar label{display:flex;align-items:center;gap:8px}.table-wrap{max-width:100%;overflow:auto}table{width:100%;min-width:900px}td{vertical-align:top}small{display:block;color:var(--muted);margin-top:4px}.sort{border:0;background:none;font:inherit;color:inherit;cursor:pointer}.key-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.key-form label,.key-secret{display:grid;gap:6px;min-width:0}.key-form input,.key-form select,.key-secret textarea{width:100%;min-width:0}.key-form .switch-field{display:flex}.wide{grid-column:1/-1}.key-secret textarea,.endpoint{overflow-wrap:anywhere;word-break:break-all}.form-actions{justify-content:flex-end;margin-top:16px}@media(max-width:600px){.key-form{grid-template-columns:minmax(0,1fr)}.key-toolbar>*{max-width:100%}}
</style>
