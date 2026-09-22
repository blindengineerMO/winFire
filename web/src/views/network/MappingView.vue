<script setup>
import {computed, onMounted, ref} from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import MappingFilters from '../../components/mapping/MappingFilters.vue'
import MappingPairsTable from '../../components/mapping/MappingPairsTable.vue'
import TopTalkersTable from '../../components/mapping/TopTalkersTable.vue'
import ArpSnapshotTable from '../../components/mapping/ArpSnapshotTable.vue'
import {mappingService} from '../../services/mapping.js'

const activeTab=ref('pairs')
const rows=ref([]),topTalkers=ref([]),arp=ref([]),nodes=ref([])
const nodeId=ref(''),external=ref(''),trafficClass=ref(''),page=ref(1),pageSize=ref(100),pages=ref(1),total=ref(0)
const loading=ref(false),error=ref(''),message=ref('')
const selectedNode=computed(()=>nodes.value.find(node=>node.id===nodeId.value))

async function load(){
  loading.value=true;error.value=''
  try{
    const [result,arpResult]=await Promise.all([mappingService.listPairs({page:page.value,pageSize:pageSize.value,nodeId:nodeId.value,external:external.value,trafficClass:trafficClass.value}),mappingService.listArp(nodeId.value)])
    rows.value=result.rows;topTalkers.value=result.topTalkers;pages.value=Math.max(result.pages,1);total.value=result.total;arp.value=arpResult.items
  }catch(cause){error.value=cause.message}
  finally{loading.value=false}
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
function changeFilter(){page.value=1;load()}
function next(delta){page.value=Math.min(pages.value,Math.max(1,page.value+delta));load()}
onMounted(async()=>{try{nodes.value=await mappingService.listNodes();await load()}catch(cause){error.value=cause.message}})
</script>

<template>
  <div class="view mapping-view">
    <PageHeader eyebrow="VISIBILITY / NETWORK MAP" title="Network mapping" description="Correlate observed traffic into internal node pairs, external connections and top talkers">
      <div class="page-actions"><button class="button secondary" @click="rebuild"><i class="mdi mdi-database-refresh-outline"></i> Rebuild map</button><button class="button primary" :disabled="loading" @click="load"><i class="mdi mdi-refresh"></i> Refresh</button></div>
    </PageHeader>
    <div v-if="error" class="error-msg">{{error}}</div><div v-if="message" class="success-msg">{{message}}</div>
    <div class="metric-grid"><div class="metric glass"><div class="metric-top"><span>MAPPED PAIRS</span><i class="mdi mdi-vector-link"></i></div><strong>{{total}}</strong><small>Observed connection patterns</small></div><div class="metric glass"><div class="metric-top"><span>TOP TALKER</span><i class="mdi mdi-swap-vertical"></i></div><strong>{{topTalkers[0]?.hostname||'—'}}</strong><small>{{topTalkers[0]?.connections||0}} connections</small></div><div class="metric glass"><div class="metric-top"><span>ARP ENTRIES</span><i class="mdi mdi-lan-connect"></i></div><strong>{{arp.length}}</strong><small>{{selectedNode?.hostname||'All managed nodes'}}</small></div><div class="metric glass"><div class="metric-top"><span>PAGE</span><i class="mdi mdi-table-large"></i></div><strong>{{page}}<span>/{{pages}}</span></strong><small>Rows {{pageSize}} per page</small></div></div>

    <nav class="view-tabs" aria-label="Network mapping sections" role="tablist">
      <button type="button" role="tab" :aria-selected="activeTab==='pairs'" :class="{active:activeTab==='pairs'}" @click="activeTab='pairs'"><i class="mdi mdi-vector-link"></i> Connections <span>{{total}}</span></button>
      <button type="button" role="tab" :aria-selected="activeTab==='talkers'" :class="{active:activeTab==='talkers'}" @click="activeTab='talkers'"><i class="mdi mdi-swap-vertical"></i> Most active nodes <span>{{topTalkers.length}}</span></button>
    </nav>

    <section v-if="activeTab==='pairs'" class="mapping-tab" role="tabpanel">
      <section class="panel glass"><div class="panel-title"><div><span class="eyebrow">CONNECTION GRAPH</span><h2>Node pairs and analyzed traffic</h2></div><MappingFilters :nodes="nodes" :node-id="nodeId" :external="external" :traffic-class="trafficClass" @update:nodeId="nodeId=$event" @update:external="external=$event" @update:trafficClass="trafficClass=$event" @change="changeFilter" /></div><MappingPairsTable :rows="rows" :loading="loading" :total="total" :page="page" :pages="pages" @previous="next(-1)" @next="next(1)" /></section>
      <ArpSnapshotTable :entries="arp" :node-selected="!!nodeId" @collect="collectArp" />
    </section>
    <section v-else class="mapping-tab" role="tabpanel"><TopTalkersTable :talkers="topTalkers" /><p class="mapping-note">Top talkers are calculated from the observed connection pairs and include both managed nodes and external peers.</p></section>
  </div>
</template>

<style scoped>
.mapping-view small{display:block;color:var(--muted);margin-top:3px}.mapping-view .metric strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}.mapping-tab{display:grid;gap:1rem}.view-tabs{display:flex;gap:.35rem;margin:.2rem 0 1rem;border-bottom:1px solid var(--border);overflow:auto}.view-tabs button{border:0;background:transparent;color:var(--muted);padding:.7rem 1rem;font:inherit;font-weight:700;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap}.view-tabs button.active{color:var(--field-value);border-bottom-color:var(--accent,#3864ae);background:color-mix(in srgb,var(--accent,#3864ae) 8%,transparent)}.view-tabs span{font-size:.72rem;margin-left:.35rem;opacity:.75}.pagination{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding:14px 16px;color:var(--muted);font-size:.72rem}.pagination span{margin-right:auto}.top-talkers-panel{min-height:220px}.talker-bar{width:100%;min-width:120px;height:7px;background:color-mix(in srgb,var(--muted) 20%,transparent);border-radius:99px;overflow:hidden}.talker-bar span{display:block;height:100%;background:var(--green,#4da17c);border-radius:inherit}.mapping-note{margin:0;color:var(--muted);font-size:.8rem}
</style>
