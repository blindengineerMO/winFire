<script setup>
import {useRoute} from 'vue-router'
const route=useRoute()
import {onMounted,onUnmounted,ref,computed,nextTick} from 'vue'
import PageHeader from '../components/PageHeader.vue'
import GlassWindow from '../components/GlassWindow.vue'
import TransactionDetailsDialog from '../components/TransactionDetailsDialog.vue'
import {api,session} from '../services/api.js'

const events=ref([]),nodes=ref([]),sessions=ref([]),policies=ref([])
const eventContext=ref(null),eventContextEl=ref(null),ruleOpen=ref(false),ruleEvent=ref(null),ruleAction=ref('allow'),rulePolicyId=ref('personal'),ruleBusy=ref(false),ignoreBusy=ref(false)
const detailOpen=ref(false),detailEvent=ref(null)
const groupPolicies=computed(()=>policies.value.filter(policy=>policy.origin!=='learned'&&policy.scopes?.some(scope=>scope.node_group_id)))
const canManageRules=computed(()=>['owner','admin'].includes(session.user?.role))
const selectedIds=ref([]),destinations=ref([]),exportDestinationId=ref(''),exportBusy=ref(false)
const filters=ref({nodeId:'',eventId:'',action:'',direction:'',srcIp:'',dstIp:'',port:'',program:'',account:'',protocol:'',challengeId:'',from:'',to:''})
const hideLoopback=ref(true)
const page=ref(1),pageSize=ref(100),total=ref(0),sortBy=ref('time'),sortDir=ref('desc')
const error=ref(''),message=ref(''),loading=ref(false),duration=ref(24)
const activeTab=ref('events'),eventType=ref('firewall')
let requestId=0
let refreshTimer=null
const pulling=ref(false)
const totalPages=computed(()=>Math.max(1,Math.ceil(total.value/pageSize.value)))
const firstRow=computed(()=>total.value?(page.value-1)*pageSize.value+1:0)
const lastRow=computed(()=>Math.min(page.value*pageSize.value,total.value))
const totals=computed(()=>({allowed:events.value.filter(e=>e.action==='allow').length,blocked:events.value.filter(e=>e.action==='block').length}))
const activeAuto=computed(()=>sessions.value.some(session=>session.node_id===filters.value.nodeId&&session.mode==='auto'&&session.status==='active'))
const nodeName=id=>nodes.value.find(node=>node.id===id)?.hostname||id?.slice(0,8)||'—'
const serviceLabel=value=>String(value||'Unidentified').split(/\r?\n/,1)[0].trim()||'Unidentified'
const serviceDetails=event=>[event.traffic_service,event.traffic_reason].filter(Boolean).join(' — ')||'Service could not be identified from the observed traffic'
const columns=[{key:'time',label:'Time'},{key:'node',label:'Node'},{key:'eventId',label:'Event'},{key:'action',label:'Action'},{key:'direction',label:'Direction'},{key:'srcIp',label:'Source'},{key:'dstIp',label:'Destination'},{key:'port',label:'Port'},{key:'service',label:'Service',sortable:false},{key:'program',label:'Program'},{key:'account',label:'Account'}]
function queryString(){
  const query={...(route.query.event?{id:String(route.query.event)}:{}),eventType:eventType.value,page:page.value,pageSize:pageSize.value,sortBy:sortBy.value,sortDir:sortDir.value,hideLoopback:hideLoopback.value,...filters.value}
  for(const key of ['from','to'])if(query[key])query[key]=new Date(query[key]).toISOString()
  return new URLSearchParams(Object.entries(query).filter(([,value])=>value!==''&&value!==null)).toString()
}
async function load(){
  const current=++requestId
  loading.value=true
  try{
    const [result,loadedSessions]=await Promise.all([api(`/logs/search?${queryString()}`),api('/learning-sessions')])
    if(current!==requestId)return
    events.value=result.items;total.value=result.total;sessions.value=loadedSessions;error.value=''
  }catch(e){if(current===requestId)error.value=e.message}
  finally{if(current===requestId)loading.value=false}
}
function searchEvents(){page.value=1;load()}
function clearFilters(){filters.value={nodeId:'',eventId:'',action:'',direction:'',srcIp:'',dstIp:'',port:'',program:'',account:'',protocol:'',challengeId:'',from:'',to:''};searchEvents()}
function switchTab(tab){activeTab.value=tab;if(tab==='events'){eventType.value='firewall';page.value=1;load()}else if(tab==='accounts'){eventType.value='logon';page.value=1;load()}}
function sort(key){if(sortBy.value===key)sortDir.value=sortDir.value==='asc'?'desc':'asc';else{sortBy.value=key;sortDir.value=key==='time'?'desc':'asc'}page.value=1;load()}
function changePage(next){if(next<1||next>totalPages.value||loading.value)return;page.value=next;load()}
async function startLearning(){if(!filters.value.nodeId)return;try{await api('/learning-sessions',{method:'POST',body:{nodeId:filters.value.nodeId,durationHours:Number(duration.value)}});await load()}catch(e){error.value=e.message}}
async function finalize(session){try{const result=await api(`/learning-sessions/${session.id}/finalize`,{method:'POST',body:{}});message.value=`Proposal generated with ${result.ruleCount} rules. Review it in Policy Studio before approval.`;await load()}catch(e){error.value=e.message}}
async function approve(session){try{const result=await api(`/learning-sessions/${session.id}/approve`,{method:'POST',body:{}});message.value=result.status==='enforced'?'Learned policy applied':result.status==='applying'?'Policy queued for agent application':'Policy apply failed; review the run before retrying';await load()}catch(e){error.value=e.message}}
async function pull(){
  const targets=nodes.value.filter(node=>['winrm','winrms'].includes(node.transport)&&(filters.value.nodeId?node.id===filters.value.nodeId:true))
  if(!targets.length)return
  error.value='';message.value='';pulling.value=true
  let inserted=0;const failures=[]
  try{
    for(const node of targets){
      try{const result=await api('/logs/pull',{method:'POST',body:{nodeId:node.id}});inserted+=result.inserted}
      catch(cause){failures.push(`${node.hostname}: ${cause.message}`)}
    }
    message.value=`Collected ${inserted} new events from ${targets.length-failures.length} node${targets.length-failures.length===1?'':'s'}.`
    page.value=1;await load()
    if(failures.length)error.value=[error.value,failures.join(' · ')].filter(Boolean).join(' · ')
  }finally{pulling.value=false}
}
function canRule(event){return !!event&&['in','out'].includes(event.direction)&&['TCP','UDP'].includes(event.protocol)&&Number(event.dst_port)>0&&!!(event.direction==='in'?event.src_ip:event.dst_ip)}
function openEventMenu(mouseEvent,event){if(!canManageRules.value)return;mouseEvent.preventDefault();const x=Math.min(mouseEvent.clientX||80,window.innerWidth-235),y=Math.min(mouseEvent.clientY||80,window.innerHeight-130);eventContext.value={event,x:Math.max(8,x),y:Math.max(8,y)};nextTick(()=>eventContextEl.value?.querySelector('button')?.focus({preventScroll:true}))}
function closeEventMenu(){eventContext.value=null}
function onPointer(event){if(eventContext.value&&!event.target.closest('.event-context-menu,.event-menu-trigger'))closeEventMenu()}
function beginRule(event,action){ruleEvent.value=event;ruleAction.value=action;rulePolicyId.value='personal';ruleOpen.value=true;closeEventMenu()}
function openEventDetails(event){detailEvent.value={...event,node_name:nodeName(event.node_id),service_name:serviceLabel(event.traffic_service)};detailOpen.value=true}
function createRuleFromDetails(action){const event=detailEvent.value;if(!event)return;detailOpen.value=false;beginRule(event,action)}
async function ignoreFromDetails(){const event=detailEvent.value;if(!event)return;detailOpen.value=false;await ignoreTraffic(event)}
function canIgnoreTraffic(event){return !!event&&([5150,5151,5156,5157].includes(Number(event.event_id))||event.event_type==='firewall')}
async function ignoreTraffic(event){if(!canIgnoreTraffic(event))return;ignoreBusy.value=true;error.value='';try{await api(`/logs/${event.id}/ignore-traffic`,{method:'POST'});message.value='Traffic ignore rule saved. Matching events are now hidden and future matches will not be stored.';closeEventMenu();page.value=1;await load()}catch(cause){error.value=cause.message}finally{ignoreBusy.value=false}}
async function addRule(){if(!ruleEvent.value)return;ruleBusy.value=true;error.value='';try{const result=await api(`/logs/${ruleEvent.value.id}/rule`,{method:'POST',body:{action:ruleAction.value,...(rulePolicyId.value==='personal'?{}:{policyId:rulePolicyId.value})}});ruleOpen.value=false;message.value=`Rule saved to policy version ${result.versionNo}. An administrator can sync it from the top bar.`;policies.value=await api('/policies')}catch(e){error.value=e.message}finally{ruleBusy.value=false}}
function toggleSelected(event){selectedIds.value=selectedIds.value.includes(event.id)?selectedIds.value.filter(id=>id!==event.id):[...selectedIds.value,event.id]}
function togglePage(){const ids=events.value.map(event=>event.id),allSelected=ids.every(id=>selectedIds.value.includes(id));selectedIds.value=allSelected?selectedIds.value.filter(id=>!ids.includes(id)):[...new Set([...selectedIds.value,...ids])]}
async function sendSelected(){if(!exportDestinationId.value||!selectedIds.value.length)return;exportBusy.value=true;error.value='';message.value='';try{const result=await api('/event-export/send',{method:'POST',body:{destinationId:exportDestinationId.value,eventIds:selectedIds.value}});message.value=`Sent ${result.sent} selected events to ${destinations.value.find(item=>item.id===exportDestinationId.value)?.name||'destination'}`;selectedIds.value=[]}catch(cause){error.value=cause.message}finally{exportBusy.value=false}}
onMounted(async()=>{window.addEventListener('pointerdown',onPointer);window.addEventListener('keydown',onMenuKey);refreshTimer=window.setInterval(()=>{if(document.visibilityState==='visible'&&page.value===1&&!loading.value&&!pulling.value)load()},30000);try{const [loadedNodes,loadedPolicies,display]=await Promise.all([api('/nodes'),api('/policies'),api('/settings/logs-display')]);nodes.value=loadedNodes;policies.value=loadedPolicies;hideLoopback.value=display.hideLoopbackEvents;if(canManageRules.value)destinations.value=await api('/event-export/destinations');await load()}catch(e){error.value=e.message}})
function onMenuKey(event){if(event.key==='Escape')closeEventMenu()}
onUnmounted(()=>{window.removeEventListener('pointerdown',onPointer);window.removeEventListener('keydown',onMenuKey);if(refreshTimer)window.clearInterval(refreshTimer)})
</script>

<template>
  <div class="view">
    <PageHeader eyebrow="OBSERVABILITY / EVENTS" title="Firewall events" description="Search collected traffic and train a policy from observed flows">
      <button class="button secondary" :disabled="pulling||!nodes.some(node=>['winrm','winrms'].includes(node.transport)&&(filters.nodeId?node.id===filters.nodeId:true))" @click="pull"><i class="mdi mdi-download-network-outline"></i> {{pulling?'Pulling…':filters.nodeId?'Pull from node':'Pull from all nodes'}}</button>
      <button class="button primary" :disabled="loading" @click="load"><i class="mdi mdi-refresh"></i> Refresh</button>
    </PageHeader>
    <div v-if="error" class="error-msg" role="alert">{{error}}</div>
    <div v-if="message" class="success-msg">{{message}}</div>
    <div class="metric-grid compact">
      <div class="metric glass"><div class="metric-top"><span>EVENTS MATCHING</span><i class="mdi mdi-text-box-search-outline"></i></div><strong>{{total}}</strong></div>
      <div class="metric glass"><div class="metric-top"><span>ALLOWED ON PAGE</span><i class="mdi mdi-check"></i></div><strong>{{totals.allowed}}</strong></div>
      <div class="metric glass"><div class="metric-top"><span>BLOCKED ON PAGE</span><i class="mdi mdi-cancel"></i></div><strong>{{totals.blocked}}</strong></div>
      <div class="metric glass"><div class="metric-top"><span>LEARNING SESSIONS</span><i class="mdi mdi-brain"></i></div><strong>{{sessions.length}}</strong></div>
    </div>
    <nav class="view-tabs" aria-label="Firewall events sections"><button type="button" :class="{active:activeTab==='events'}" @click="switchTab('events')">Firewall events <span>{{eventType==='firewall'?total:'—'}}</span></button><button type="button" :class="{active:activeTab==='accounts'}" @click="switchTab('accounts')">Accounts <span>{{eventType==='logon'?total:'—'}}</span></button><button type="button" :class="{active:activeTab==='learning'}" @click="switchTab('learning')">Learning sessions <span>{{sessions.length}}</span></button></nav>
    <section v-if="activeTab==='events'||activeTab==='accounts'" class="panel glass">
      <div class="panel-title"><div><span class="eyebrow">EVENT SEARCH</span><h2>{{activeTab==='accounts'?'Accounts logon and logoff':'Traffic log'}}</h2></div><div class="table-tools"><label class="page-size">Rows per page <select v-model.number="pageSize" @change="searchEvents"><option :value="25">25</option><option :value="50">50</option><option :value="100">100</option><option :value="200">200</option><option :value="500">500</option></select></label></div></div>
      <form class="log-filters" @submit.prevent="searchEvents">
        <label>Protocol<input v-model.trim="filters.protocol" placeholder="TCP, UDP…"></label>
        <label>Challenge ID<input v-model.trim="filters.challengeId" placeholder="MFA challenge ID"></label>
        <label>From<input v-model="filters.from" type="datetime-local"></label>
        <label>To<input v-model="filters.to" type="datetime-local"></label>
        <label class="switch-field"><span>Hide local loopback</span><input v-model="hideLoopback" type="checkbox" role="switch" @change="searchEvents"><span class="switch-control" aria-hidden="true"></span></label>
        <button class="button small primary" :disabled="loading">Apply filters</button>
        <button type="button" class="button small secondary" @click="clearFilters">Clear filters</button>
      </form>
      <div v-if="canManageRules" class="event-export-bar"><label class="check-label"><input type="checkbox" :checked="events.length>0&&events.every(event=>selectedIds.includes(event.id))" @change="togglePage"> Select page</label><span>{{selectedIds.length}} selected</span><select v-model="exportDestinationId" aria-label="Event export destination"><option value="">Choose export destination</option><option v-for="destination in destinations" :key="destination.id" :value="destination.id">{{destination.name}} · {{destination.kind==='splunk_hec'?'Splunk HEC':'Syslog TLS'}}</option></select><button class="button small secondary" :disabled="exportBusy||!exportDestinationId||!selectedIds.length||selectedIds.length>500" @click="sendSelected">{{exportBusy?'Sending…':'Export selected'}}</button><button v-if="selectedIds.length" class="button small secondary" @click="selectedIds=[]">Clear</button><small v-if="!destinations.length">Configure destinations in Administration → Logs and DNS.</small></div>
      <div class="table-wrap events-table-wrap"><table class="events-table"><thead>
        <tr><th v-if="canManageRules" aria-label="Select events"><span class="sr-only">Select events</span></th><th v-for="column in columns" :key="column.key" :aria-sort="column.sortable===false?undefined:sortBy===column.key?(sortDir==='asc'?'ascending':'descending'):undefined"><button v-if="column.sortable!==false" type="button" class="sort-heading" :aria-label="`Sort by ${column.label}`" @click="sort(column.key)">{{column.label}} <i :class="sortBy===column.key?(sortDir==='asc'?'mdi mdi-arrow-up':'mdi mdi-arrow-down'):'mdi mdi-swap-vertical'"></i></button><span v-else>{{column.label}}</span></th><th v-if="canManageRules">Actions</th></tr>
        <tr class="column-filters">
          <th v-if="canManageRules" aria-label="Select events"><span class="sr-only">Select events</span></th>
          <th><span class="filter-hint">Use dates above</span></th>
          <th><select v-model="filters.nodeId" aria-label="Filter node" @change="searchEvents"><option value="">All nodes</option><option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select></th>
          <th><input v-model="filters.eventId" type="number" min="0" placeholder="ID" aria-label="Filter event ID" @keyup.enter="searchEvents"></th>
          <th><select v-model="filters.action" aria-label="Filter action" @change="searchEvents"><option value="">All</option><option value="allow">Allow</option><option value="block">Block</option><option value="success">Success</option><option value="failure">Failure</option><option value="logon">Logon</option><option value="logoff">Logoff</option></select></th>
          <th><select v-model="filters.direction" aria-label="Filter direction" @change="searchEvents"><option value="">All</option><option value="in">Inbound</option><option value="out">Outbound</option></select></th>
          <th><input v-model.trim="filters.srcIp" placeholder="Source IP" aria-label="Filter source IP" @keyup.enter="searchEvents"></th>
          <th><input v-model.trim="filters.dstIp" placeholder="Destination IP" aria-label="Filter destination IP" @keyup.enter="searchEvents"></th>
          <th><input v-model="filters.port" type="number" min="1" max="65535" placeholder="Port" aria-label="Filter destination port" @keyup.enter="searchEvents"></th><th aria-label="Filter service"><span class="sr-only">Service is identified from protocol and port</span></th>
          <th><input v-model.trim="filters.program" placeholder="Program" aria-label="Filter program" @keyup.enter="searchEvents"></th><th><input v-model.trim="filters.account" placeholder="Account or SID" aria-label="Filter account" @keyup.enter="searchEvents"></th><th aria-label="Event actions"><span class="sr-only">Event actions</span></th>
        </tr>
      </thead><tbody>
        <tr v-for="event in events" :key="event.id" tabindex="0" class="transaction-row" @click="openEventDetails(event)" @keydown.enter="openEventDetails(event)" @contextmenu="openEventMenu($event,event)" @keydown.shift.f10="openEventMenu($event,event)"><td v-if="canManageRules"><input type="checkbox" :checked="selectedIds.includes(event.id)" :aria-label="`Select event ${event.event_id} at ${event.event_time||event.received_at}`" @click.stop @change="toggleSelected(event)"></td><td>{{new Date(event.event_time||event.received_at).toLocaleString()}}</td><td class="mono">{{nodeName(event.node_id)}}</td><td>{{event.event_id}}</td><td><span class="status" :class="event.action">{{event.action}}</span></td><td>{{event.direction||'—'}}</td><td class="mono">{{event.src_ip||'—'}}</td><td class="mono">{{event.dst_ip||'—'}}</td><td class="mono">{{event.dst_port||'—'}}</td><td class="service-cell" :title="serviceDetails(event)" :aria-label="serviceDetails(event)"><strong>{{serviceLabel(event.traffic_service)}}</strong></td><td class="mono">{{event.program||'—'}}</td><td class="mono" :title="event.account_sid||''">{{event.account_name||event.account_sid||'—'}}</td><td v-if="canManageRules"><button class="icon-button event-menu-trigger" :aria-label="`Actions for event ${event.event_id}`" @click.stop="openEventMenu($event,event)"><i class="mdi mdi-dots-vertical"></i></button></td></tr>
        <tr v-if="!events.length"><td :colspan="canManageRules?13:11" class="empty-table">{{loading?'Loading events…':'No events found. Pull the Windows Security log or adjust filters.'}}</td></tr>
      </tbody></table></div>
      <div class="event-pagination" role="navigation" aria-label="Firewall events pages"><span>Showing {{firstRow}}–{{lastRow}} of {{total}}</span><div><button type="button" class="button small secondary" :disabled="page<=1||loading" @click="changePage(page-1)">Previous</button><span>Page {{page}} of {{totalPages}}</span><button type="button" class="button small secondary" :disabled="page>=totalPages||loading" @click="changePage(page+1)">Next</button></div></div>
    </section>
    <section v-if="activeTab==='learning'" class="panel glass"><div class="panel-title"><div><span class="eyebrow">POLICY DISCOVERY</span><h2>Learning sessions</h2></div><div class="table-tools"><input v-model.number="duration" type="number" min="1" max="720" aria-label="Duration in hours" style="width:90px"><span class="hint">hours</span><button class="button small secondary" :disabled="!filters.nodeId" @click="startLearning">{{activeAuto?'Switch to manual review':'Start manual learning'}}</button></div></div><div v-for="session in sessions" :key="session.id" class="history-row"><div><strong>{{nodeName(session.node_id)}}</strong><small>{{session.mode==='auto'?'Automatic':'Manual review'}} · {{session.status}} · ends {{new Date(session.ends_at).toLocaleString()}}</small><small v-if="session.last_error" class="danger-text">{{session.last_error}}</small></div><router-link v-if="session.generated_policy_id" class="button small secondary" :to="{path:'/policies',query:{policyId:session.generated_policy_id}}">Review policy</router-link><button v-if="session.status==='active'&&session.mode!=='auto'" class="button small secondary" @click="finalize(session)">Generate proposal</button><button v-if="['review','apply-failed'].includes(session.status)" class="button small primary" @click="approve(session)">{{session.mode==='auto'?'Retry apply':'Approve and apply'}}</button></div><div v-if="!sessions.length" class="empty-side">No learning sessions yet.</div></section>
    <div v-if="eventContext" ref="eventContextEl" class="event-context-menu" role="menu" :style="{left:`${eventContext.x}px`,top:`${eventContext.y}px`}" @contextmenu.prevent><strong>Event {{eventContext.event.event_id}} · {{nodeName(eventContext.event.node_id)}}</strong><button role="menuitem" :disabled="ignoreBusy||!canIgnoreTraffic(eventContext.event)" @click="ignoreTraffic(eventContext.event)"><i class="mdi mdi-filter-off-outline"></i> Ignore like traffic</button><button role="menuitem" :disabled="!canRule(eventContext.event)" @click="beginRule(eventContext.event,'allow')"><i class="mdi mdi-check-circle-outline"></i> Add allow rule…</button><button role="menuitem" :disabled="!canRule(eventContext.event)" @click="beginRule(eventContext.event,'block')"><i class="mdi mdi-cancel"></i> Add reject rule…</button></div>
    <TransactionDetailsDialog v-model="detailOpen" :transaction="detailEvent" title="Firewall transaction details" :can-allow="canManageRules&&canRule(detailEvent)" :can-deny="canManageRules&&canRule(detailEvent)" :can-ignore="canManageRules&&canIgnoreTraffic(detailEvent)" :busy="ruleBusy||ignoreBusy" @allow="createRuleFromDetails('allow')" @deny="createRuleFromDetails('block')" @ignore="ignoreFromDetails" />
    <GlassWindow v-model="ruleOpen" title="Create rule from firewall event" width="560px"><div v-if="ruleEvent" class="form-grid"><p>{{nodeName(ruleEvent.node_id)}} · {{ruleEvent.direction}}bound {{ruleEvent.protocol}} {{ruleEvent.dst_port}} · {{ruleEvent.direction==='in'?ruleEvent.src_ip:ruleEvent.dst_ip}}</p><label>Action<select v-model="ruleAction"><option value="allow">Allow</option><option value="block">Reject</option></select></label><label>Policy<select v-model="rulePolicyId"><option value="personal">{{nodeName(ruleEvent.node_id)}} personal policy</option><option v-for="policy in groupPolicies" :key="policy.id" :value="policy.id">{{policy.name}} · group/global</option></select></label><p class="muted">The rule is staged in a new version. It will reach enforced nodes when an administrator syncs policies.</p><div class="form-actions"><button class="button secondary" @click="ruleOpen=false">Cancel</button><button class="button primary" :disabled="ruleBusy" @click="addRule">{{ruleBusy?'Saving…':'Create rule'}}</button></div></div></GlassWindow>
  </div>
</template>

<style scoped>
.view-tabs{display:flex;gap:.35rem;margin:.2rem 0 1rem;border-bottom:1px solid var(--border);overflow:auto}.view-tabs button{border:0;background:transparent;color:var(--muted);padding:.7rem 1rem;font:inherit;font-weight:700;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap}.view-tabs button.active{color:var(--field-value);border-bottom-color:var(--accent,#3864ae);background:color-mix(in srgb,var(--accent,#3864ae) 8%,transparent)}.view-tabs span{font-size:.72rem;margin-left:.35rem;opacity:.75}.page-size{display:flex;align-items:center;gap:.55rem;white-space:nowrap;font-size:.8rem}.page-size select{min-width:75px}
.event-export-bar{display:flex;align-items:center;gap:.65rem;flex-wrap:wrap;padding:.65rem 1rem;border-top:1px solid var(--border);font-size:.78rem}.event-export-bar select{min-width:230px;max-width:100%}.event-export-bar small{color:var(--muted)}.event-export-bar .check-label{display:flex;align-items:center;gap:.35rem}
.events-table{min-width:1150px}.events-table th{white-space:nowrap}.sort-heading{display:flex;align-items:center;gap:.4rem;border:0;background:none;color:inherit;font:inherit;font-weight:700;text-transform:uppercase;cursor:pointer;padding:0}.sort-heading i{font-size:1rem;opacity:.7}.sort-heading:hover,.sort-heading:focus-visible{color:var(--accent,#3864ae)}
.service-cell{width:170px;max-width:170px}.service-cell strong{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.72rem;line-height:1.25}
.column-filters th{padding:.45rem .35rem}.column-filters input,.column-filters select{width:100%;min-width:85px;box-sizing:border-box;font-size:.75rem}.column-filters th:first-child{min-width:130px}.column-filters th:nth-child(2){min-width:125px}.column-filters th:last-child{min-width:180px}.filter-hint{font-size:.72rem;font-weight:400;text-transform:none;opacity:.75}.event-pagination{display:flex;justify-content:space-between;align-items:center;gap:1rem;padding:.85rem 1rem;font-size:.8rem}.event-pagination>div{display:flex;align-items:center;gap:.7rem}
.event-context-menu{position:fixed;z-index:1000;min-width:220px;display:grid;padding:6px;background:var(--panel);color:var(--field-value);border:1px solid var(--border);border-radius:7px;box-shadow:0 20px 55px #0005}.event-context-menu strong{font-size:.68rem;padding:8px 10px;color:var(--muted)}.event-context-menu button{border:0;background:transparent;color:inherit;text-align:left;padding:9px 10px;border-radius:4px;font-size:.75rem;cursor:pointer}.event-context-menu button:hover{background:color-mix(in srgb,var(--green) 18%,transparent)}.event-context-menu button:disabled{opacity:.45;cursor:not-allowed}
.transaction-row{cursor:pointer}.transaction-row:hover,.transaction-row:focus-visible{background:color-mix(in srgb,var(--accent,#3864ae) 8%,transparent)}
@media(max-width:700px){.event-pagination{flex-direction:column;align-items:flex-start}.log-filters{grid-template-columns:repeat(auto-fit,minmax(130px,1fr))}}
</style>
