<script setup>
import {useRoute} from 'vue-router'
const route=useRoute()
import {computed, onMounted, ref} from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import MappingFilters from '../../components/mapping/MappingFilters.vue'
import MappingPairsTable from '../../components/mapping/MappingPairsTable.vue'
import TopTalkersTable from '../../components/mapping/TopTalkersTable.vue'
import ArpSnapshotTable from '../../components/mapping/ArpSnapshotTable.vue'
import TopologyGraph from '../../components/mapping/TopologyGraph.vue'
import GlassWindow from '../../components/GlassWindow.vue'
import TransactionDetailsDialog from '../../components/TransactionDetailsDialog.vue'
import {api,session} from '../../services/api.js'
import {mappingService} from '../../services/mapping.js'

const activeTab=ref('pairs')
const rows=ref([]),topTalkers=ref([]),arp=ref([]),topology=ref({nodes:[],edges:[],nodeCount:0,edgeCount:0}),nodes=ref([]),policies=ref([])
const emptyFilters=()=>({nodeId:'',external:'',trafficClass:'',subnet:'',switchId:'',from:'',to:''})
const draft=ref({...emptyFilters(),nodeId:String(route.query.nodeId||'')}),applied=ref({...emptyFilters(),nodeId:String(route.query.nodeId||'')}),filterOptions=ref({switches:[],subnets:[]})
const nodeId=computed(()=>applied.value.nodeId)
const page=ref(1),pageSize=ref(100),pages=ref(1),total=ref(0)
const loading=ref(false),error=ref(''),message=ref(''),topologySelectedId=ref('')
const selectedNode=computed(()=>nodes.value.find(node=>node.id===nodeId.value))
const canManageRules=computed(()=>['owner','admin'].includes(session.user?.role))
const detailOpen=ref(false),selectedRow=ref(null),representativeEvent=ref(null),detailLoading=ref(false)
const ruleOpen=ref(false),ruleAction=ref('allow'),rulePolicyId=ref('personal'),ruleBusy=ref(false),ignoreBusy=ref(false)
const groupPolicies=computed(()=>policies.value.filter(policy=>policy.origin!=='learned'&&policy.scopes?.some(scope=>scope.node_group_id)))
const canRule=event=>!!event&&['in','out'].includes(event.direction)&&['TCP','UDP'].includes(event.protocol)&&Number(event.dst_port)>0&&!!(event.direction==='in'?event.src_ip:event.dst_ip)
const canIgnore=event=>!!event&&([5150,5151,5156,5157].includes(Number(event.event_id))||event.event_type==='firewall')

let loadSequence=0
async function load(){
  const sequence=++loadSequence
  loading.value=true;error.value=''
  try{
    const filters={...applied.value}
    for(const key of ['from','to'])if(filters[key])filters[key]=new Date(filters[key]).toISOString()
    const [result,arpResult,topologyResult]=await Promise.all([mappingService.listPairs({...filters,page:page.value,pageSize:pageSize.value}),mappingService.listArp(filters),mappingService.listTopology(filters)])
    if(sequence!==loadSequence)return
    rows.value=result.rows;topTalkers.value=result.topTalkers;pages.value=Math.max(result.pages,1);total.value=result.total;arp.value=arpResult.items;topology.value=topologyResult
  }catch(cause){if(sequence===loadSequence){error.value=cause.message;rows.value=[];topTalkers.value=[];arp.value=[];topology.value={nodes:[],edges:[]};total.value=0;pages.value=1}}
  finally{if(sequence===loadSequence)loading.value=false}
}
async function collectArp(){
  if(!nodeId.value)return
  message.value=''
  try{await mappingService.collectArp(nodeId.value);message.value='ARP collection queued. Refresh in a moment.'}
  catch(cause){error.value=cause.message}
}
async function rebuild(){
  message.value='';error.value=''
  try{const result=await mappingService.rebuild();message.value=`Rebuilt ${result.rows} mapping pair${result.rows===1?'':'s'} from ${result.events} events.`;await load()}
  catch(cause){error.value=cause.message}
}
function changeFilter(){
  if(draft.value.from&&draft.value.to&&new Date(draft.value.from)>new Date(draft.value.to)){error.value='From must be before To';return}
  applied.value={...draft.value,subnet:draft.value.subnet.trim()};page.value=1;topologySelectedId.value='';load()
}
function clearFilters(){draft.value=emptyFilters();changeFilter()}
function next(delta){page.value=Math.min(pages.value,Math.max(1,page.value+delta));load()}
function openTransaction(row){selectedRow.value=row;representativeEvent.value=null;detailOpen.value=true;detailLoading.value=true;mappingService.findRepresentativeEvent(row).then(event=>{representativeEvent.value=event}).catch(cause=>{error.value=cause.message}).finally(()=>{detailLoading.value=false})}
function selectTopologyNode(node){const assetId=node.id.startsWith('asset:')?node.id.slice(6):'';if(assetId&&nodes.value.some(item=>item.id===assetId)){draft.value={...applied.value,nodeId:assetId};changeFilter()}topologySelectedId.value=node.id}
function beginRule(action){if(!representativeEvent.value)return;ruleAction.value=action;rulePolicyId.value='personal';ruleOpen.value=true;detailOpen.value=false}
async function addRule(){if(!representativeEvent.value)return;ruleBusy.value=true;error.value='';try{const result=await mappingService.createRule(representativeEvent.value.id,ruleAction.value,rulePolicyId.value);message.value=`Rule saved to policy version ${result.versionNo}. An administrator can sync it from the top bar.`;ruleOpen.value=false}catch(cause){error.value=cause.message}finally{ruleBusy.value=false}}
async function ignoreTransaction(){if(!representativeEvent.value)return;ignoreBusy.value=true;error.value='';try{await mappingService.ignoreEvent(representativeEvent.value.id);message.value='Traffic ignore rule saved. Matching events are now hidden and future matches will not be stored.';detailOpen.value=false;await load()}catch(cause){error.value=cause.message}finally{ignoreBusy.value=false}}
onMounted(async()=>{try{[nodes.value,policies.value,filterOptions.value]=await Promise.all([mappingService.listNodes(),api('/policies'),mappingService.filterOptions()]);await load()}catch(cause){error.value=cause.message}})
</script>

<template>
  <div class="view mapping-view">
    <PageHeader eyebrow="VISIBILITY / NETWORK MAP" title="Network mapping" description="Correlate observed traffic into internal node pairs, external connections and top talkers">
      <div class="page-actions"><button class="button secondary" @click="rebuild"><i class="mdi mdi-database-refresh-outline"></i> Rebuild map</button><button class="button primary" :disabled="loading" @click="load"><i class="mdi mdi-refresh"></i> Refresh</button></div>
    </PageHeader>
    <div v-if="error" class="error-msg">{{error}}</div><div v-if="message" class="success-msg">{{message}}</div>
    <div class="metric-grid"><div class="metric glass"><div class="metric-top"><span>MAPPED PAIRS</span><i class="mdi mdi-vector-link"></i></div><strong>{{total}}</strong><small>Observed connection patterns</small></div><div class="metric glass"><div class="metric-top"><span>TOP TALKER</span><i class="mdi mdi-swap-vertical"></i></div><strong>{{topTalkers[0]?.hostname||'—'}}</strong><small>{{topTalkers[0]?.connections||0}} connections</small></div><div class="metric glass"><div class="metric-top"><span>ARP ENTRIES</span><i class="mdi mdi-lan-connect"></i></div><strong>{{arp.length}}</strong><small>{{selectedNode?.hostname||'All managed nodes'}}</small></div><div class="metric glass"><div class="metric-top"><span>PAGE</span><i class="mdi mdi-table-large"></i></div><strong>{{page}}<span>/{{pages}}</span></strong><small>Rows {{pageSize}} per page</small></div></div>

    <MappingFilters v-model="draft" :nodes="nodes" :switches="filterOptions.switches" :subnets="filterOptions.subnets" :busy="loading" @apply="changeFilter" @reset="clearFilters" />
    <nav class="view-tabs" aria-label="Network mapping sections" role="tablist">
      <button type="button" role="tab" :aria-selected="activeTab==='pairs'" :class="{active:activeTab==='pairs'}" @click="activeTab='pairs'"><i class="mdi mdi-vector-link"></i> Connections <span>{{total}}</span></button>
      <button type="button" role="tab" :aria-selected="activeTab==='topology'" :class="{active:activeTab==='topology'}" @click="activeTab='topology';load()"><i class="mdi mdi-graph-outline"></i> Topology <span>{{topology.nodeCount||0}}</span></button>
      <button type="button" role="tab" :aria-selected="activeTab==='talkers'" :class="{active:activeTab==='talkers'}" @click="activeTab='talkers'"><i class="mdi mdi-swap-vertical"></i> Most active nodes <span>{{topTalkers.length}}</span></button>
      <button type="button" role="tab" :aria-selected="activeTab==='neighbors'" :class="{active:activeTab==='neighbors'}" @click="activeTab='neighbors'"><i class="mdi mdi-lan-connect"></i> Neighbors <span>{{arp.length}}</span></button>
    </nav>

    <section v-if="activeTab==='pairs'" class="mapping-tab" role="tabpanel">
      <section class="panel glass"><div class="panel-title"><div><span class="eyebrow">CONNECTION GRAPH</span><h2>Node pairs and analyzed traffic</h2></div></div><MappingPairsTable :rows="rows" :loading="loading" :total="total" :page="page" :pages="pages" @previous="next(-1)" @next="next(1)" @select="openTransaction" /></section>
    </section>
    <section v-else-if="activeTab==='topology'" class="mapping-tab" role="tabpanel"><TopologyGraph :graph="topology" :selected-id="topologySelectedId" @select="selectTopologyNode" /></section>
    <section v-else-if="activeTab==='talkers'" class="mapping-tab" role="tabpanel"><TopTalkersTable :talkers="topTalkers" /><p class="mapping-note">Top talkers are calculated from the observed connection pairs and include both managed nodes and external peers.</p></section>
    <section v-else class="mapping-tab" role="tabpanel"><ArpSnapshotTable :entries="arp" :node-selected="!!nodeId" @collect="collectArp" /></section>
    <TransactionDetailsDialog v-model="detailOpen" :transaction="selectedRow" title="Network transaction details" :can-allow="canManageRules&&canRule(representativeEvent)" :can-deny="canManageRules&&canRule(representativeEvent)" :can-ignore="canManageRules&&canIgnore(representativeEvent)" :loading-actions="detailLoading" :busy="ruleBusy||ignoreBusy" @allow="beginRule('allow')" @deny="beginRule('block')" @ignore="ignoreTransaction" />
    <GlassWindow v-model="ruleOpen" title="Create rule from network transaction" width="560px"><div v-if="representativeEvent" class="form-grid"><p>{{representativeEvent.direction==='in'?'Inbound':'Outbound'}} {{representativeEvent.protocol}} {{representativeEvent.dst_port}} · {{representativeEvent.direction==='in'?representativeEvent.src_ip:representativeEvent.dst_ip}}</p><label>Action<select v-model="ruleAction"><option value="allow">Allow</option><option value="block">Reject</option></select></label><label>Policy<select v-model="rulePolicyId"><option value="personal">{{representativeEvent.node_name||representativeEvent.node_id}} personal policy</option><option v-for="policy in groupPolicies" :key="policy.id" :value="policy.id">{{policy.name}} · group/global</option></select></label><p class="muted">The rule is staged in a new version. It will reach enforced nodes when an administrator syncs policies.</p><div class="form-actions"><button class="button secondary" @click="ruleOpen=false">Cancel</button><button class="button primary" :disabled="ruleBusy" @click="addRule">{{ruleBusy?'Saving…':'Create rule'}}</button></div></div></GlassWindow>
  </div>
</template>

<style scoped>
.mapping-view small{display:block;color:var(--muted);margin-top:3px}.mapping-view .metric strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}.mapping-tab{display:grid;gap:1rem}.view-tabs{display:flex;gap:.35rem;margin:.2rem 0 1rem;border-bottom:1px solid var(--border);overflow:auto}.view-tabs button{border:0;background:transparent;color:var(--muted);padding:.7rem 1rem;font:inherit;font-weight:700;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap}.view-tabs button.active{color:var(--field-value);border-bottom-color:var(--accent,#3864ae);background:color-mix(in srgb,var(--accent,#3864ae) 8%,transparent)}.view-tabs span{font-size:.72rem;margin-left:.35rem;opacity:.75}.pagination{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding:14px 16px;color:var(--muted);font-size:.72rem}.pagination span{margin-right:auto}.top-talkers-panel{min-height:220px}.talker-bar{width:100%;min-width:120px;height:7px;background:color-mix(in srgb,var(--muted) 20%,transparent);border-radius:99px;overflow:hidden}.talker-bar span{display:block;height:100%;background:var(--green,#4da17c);border-radius:inherit}.mapping-note{margin:0;color:var(--muted);font-size:.8rem}
.mapping-view :deep(.mapping-row){cursor:pointer}.mapping-view :deep(.mapping-row:hover),.mapping-view :deep(.mapping-row:focus-visible){background:color-mix(in srgb,var(--accent,#3864ae) 8%,transparent)}
.neighbor-filter{display:flex;align-items:end;gap:1rem;flex-wrap:wrap}.neighbor-filter label{display:grid;gap:.3rem;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em}.neighbor-filter select{min-width:220px}
</style>
