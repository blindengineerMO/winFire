<script setup>
import {computed,onMounted,ref} from 'vue'
import {api} from '../../services/api.js'
const events=ref([]),devices=ref([]),summary=ref({events:0,domains:0,devices:0,blocked:0,unmappedUsers:0})
const loading=ref(false),error=ref(''),page=ref(1),pageSize=ref(100),total=ref(0),totalPages=ref(0)
const filters=ref({q:'',domain:'',path:'',browser:'',action:'',deviceId:'',userId:'',from:'',to:''})
const sortBy=ref('time'),sortDir=ref('desc')
const hasFilters=computed(()=>Object.values(filters.value).some(Boolean))
function query(){
  const params=new URLSearchParams({page:String(page.value),pageSize:String(pageSize.value),sortBy:sortBy.value,sortDir:sortDir.value})
  for(const [key,value] of Object.entries(filters.value))if(value)params.set(key,key==='from'||key==='to'?new Date(value).toISOString():value)
  return params.toString()
}
async function load(){
  loading.value=true;error.value=''
  try{
    const [result,stats,listed]=await Promise.all([api(`/internet/events?${query()}`),api('/internet/summary'),api('/internet/devices')])
    events.value=result.items;total.value=result.total;totalPages.value=result.totalPages;summary.value=stats;devices.value=listed
  }catch(cause){error.value=cause.message}
  finally{loading.value=false}
}
function apply(){page.value=1;load()}
function reset(){filters.value={q:'',domain:'',path:'',browser:'',action:'',deviceId:'',userId:'',from:'',to:''};apply()}
function sort(column){if(sortBy.value===column)sortDir.value=sortDir.value==='asc'?'desc':'asc';else{sortBy.value=column;sortDir.value='asc'};load()}
function move(next){if(next<1||next>totalPages.value)return;page.value=next;load()}

function nodeLabel(event){return event.node_hostname||event.node_group_name||'Unmapped device'}
onMounted(load)
defineExpose({refresh:load})
</script>
<template><div><div v-if="error" class="error-msg" role="alert">{{error}}</div>    <section class="metric-grid internet-metrics"><article class="metric glass"><div class="metric-top">EVENTS <i class="mdi mdi-web"></i></div><strong>{{summary.events.toLocaleString()}}</strong><small>retained navigation events</small></article><article class="metric glass"><div class="metric-top">DOMAINS <i class="mdi mdi-domain"></i></div><strong>{{summary.domains.toLocaleString()}}</strong><small>unique registrable domains</small></article><article class="metric glass"><div class="metric-top">DEVICES <i class="mdi mdi-monitor-eye"></i></div><strong>{{summary.devices.toLocaleString()}}</strong><small>enrolled browsers</small></article><article class="metric glass"><div class="metric-top">BLOCKED <i class="mdi mdi-cancel"></i></div><strong>{{summary.blocked.toLocaleString()}}</strong><small>policy decisions</small></article><article class="metric glass"><div class="metric-top">UNMAPPED <i class="mdi mdi-account-question-outline"></i></div><strong>{{summary.unmappedUsers.toLocaleString()}}</strong><small>events without a bound user</small></article></section>
    <section class="panel glass internet-panel"><div class="panel-title"><div><span class="eyebrow">BROWSER TELEMETRY</span><h2>Internet events</h2></div><span class="count-chip">{{total.toLocaleString()}} matching</span></div>
      <form class="internet-filters" @submit.prevent="apply"><label>Search hostname or path<input v-model.trim="filters.q" placeholder="portal.example.com or /accounts"></label><label>Domain<input v-model.trim="filters.domain" placeholder="example.com"></label><label>Path prefix<input v-model.trim="filters.path" placeholder="/admin"></label><label>Browser<select v-model="filters.browser"><option value="">All browsers</option><option value="chrome">Chrome</option><option value="edge">Edge</option><option value="firefox">Firefox</option></select></label><label>Action<select v-model="filters.action"><option value="">All actions</option><option value="observed">Observed</option><option value="allowed">Allowed</option><option value="blocked">Blocked</option></select></label><label>Device<select v-model="filters.deviceId"><option value="">All devices</option><option v-for="device in devices" :key="device.id" :value="device.id">{{device.nodeHostname||device.nodeGroupName||device.id}}</option></select></label><label>User<select v-model="filters.userId"><option value="">All users</option><option v-for="device in devices.filter(item=>item.userId)" :key="device.userId" :value="device.userId">{{device.userEmail||device.userId}}</option></select></label><label>From<input v-model="filters.from" type="datetime-local"></label><label>To<input v-model="filters.to" type="datetime-local"></label><div class="form-actions"><button class="button primary">Apply filters</button><button type="button" class="button secondary" :disabled="!hasFilters" @click="reset">Clear</button></div></form>
      <div class="table-wrap"><table><thead><tr><th :aria-sort="sortBy==='time'?(sortDir==='asc'?'ascending':'descending'):undefined"><button type="button" class="table-sort" @click="sort('time')">TIME <span>{{sortBy==='time'?(sortDir==='asc'?'↑':'↓'):''}}</span></button></th><th :aria-sort="sortBy==='domain'?(sortDir==='asc'?'ascending':'descending'):undefined"><button type="button" class="table-sort" @click="sort('domain')">DOMAIN <span>{{sortBy==='domain'?(sortDir==='asc'?'↑':'↓'):''}}</span></button></th><th :aria-sort="sortBy==='hostname'?(sortDir==='asc'?'ascending':'descending'):undefined"><button type="button" class="table-sort" @click="sort('hostname')">HOSTNAME <span>{{sortBy==='hostname'?(sortDir==='asc'?'↑':'↓'):''}}</span></button></th><th>PATH</th><th :aria-sort="sortBy==='browser'?(sortDir==='asc'?'ascending':'descending'):undefined"><button type="button" class="table-sort" @click="sort('browser')">BROWSER <span>{{sortBy==='browser'?(sortDir==='asc'?'↑':'↓'):''}}</span></button></th><th>DEVICE / NODE</th><th>USER</th><th :aria-sort="sortBy==='action'?(sortDir==='asc'?'ascending':'descending'):undefined"><button type="button" class="table-sort" @click="sort('action')">ACTION <span>{{sortBy==='action'?(sortDir==='asc'?'↑':'↓'):''}}</span></button></th></tr></thead><tbody><tr v-for="event in events" :key="event.id"><td>{{new Date(event.observed_at).toLocaleString()}}</td><td class="mono">{{event.registrable_domain}}</td><td class="mono">{{event.hostname}}</td><td class="mono">{{event.path_prefix||'—'}}</td><td>{{event.browser}}</td><td>{{nodeLabel(event)}}</td><td>{{event.user_email||'Unmapped'}}</td><td><span class="status" :class="event.action">{{event.action}}</span></td></tr><tr v-if="!events.length"><td colspan="8" class="empty-table">{{loading?'Loading…':'No Internet events match the selected filters.'}}</td></tr></tbody></table></div>
      <div class="internet-pagination"><span>Showing {{events.length?((page-1)*pageSize+1):0}}–{{Math.min(page*pageSize,total)}} of {{total}}</span><div><button class="button small secondary" :disabled="page<=1||loading" @click="move(page-1)">Previous</button><span>Page {{page}} of {{Math.max(totalPages,1)}}</span><button class="button small secondary" :disabled="page>=totalPages||loading" @click="move(page+1)">Next</button></div></div>
    </section>
</div></template>
<style scoped src="./internet.css"></style>
