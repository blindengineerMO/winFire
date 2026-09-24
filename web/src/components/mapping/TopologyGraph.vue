<script setup>
import {computed, ref} from 'vue'

const props=defineProps({graph:{type:Object,default:()=>({nodes:[],edges:[]})},selectedId:{type:String,default:''}})
const emit=defineEmits(['select'])
const zoom=ref(1)
const width=1100
const positions=computed(()=>{
  const nodes=props.graph.nodes||[]
  const infrastructure=nodes.filter(node=>['switch','router','firewall','hypervisor'].includes(node.role))
  const endpoints=nodes.filter(node=>!infrastructure.includes(node))
  const result=new Map()
  const placeRow=(items,y)=>items.forEach((node,index)=>result.set(node.id,{x:(index+1)*width/(items.length+1),y}))
  placeRow(infrastructure,120)
  const columns=Math.max(1,Math.min(8,Math.ceil(Math.sqrt(Math.max(endpoints.length,1)))))
  const rows=Math.max(1,Math.ceil(endpoints.length/columns))
  endpoints.forEach((node,index)=>{const row=Math.floor(index/columns),column=index%columns;result.set(node.id,{x:(column+1)*width/(Math.min(columns,endpoints.length)+1),y:300+row*105})})
  return {result,height:Math.max(470,360+rows*105)}
})
const graphEdges=computed(()=>({edges:(props.graph.edges||[]).map(edge=>({...edge,from:positions.value.result.get(edge.source),to:positions.value.result.get(edge.target)})).filter(edge=>edge.from&&edge.to),height:positions.value.height}))
const nodeLabel=node=>node.kind==='peer'?`${node.label} (observed)`:`${node.label}${node.address?` · ${node.address}`:''}`
const roleLabel=role=>({switch:'Switch',router:'Router',firewall:'Firewall',hypervisor:'Hypervisor',host:'Host'})[role]||'Device'
function select(node){emit('select',node)}
function adjust(delta){zoom.value=Math.max(.65,Math.min(1.7,Number((zoom.value+delta).toFixed(2))))}
</script>

<template>
  <section class="topology-panel panel glass">
    <div class="panel-title topology-title"><div><span class="eyebrow">TOPOLOGY GRAPH</span><h2>Network relationships</h2><p class="muted">Links combine observed traffic, ARP neighbors, and SNMP forwarding entries.</p></div><div class="topology-actions"><span class="muted">{{graph.nodeCount||0}} nodes · {{graph.edgeCount||0}} links</span><button type="button" class="button small secondary" @click="adjust(-.1)" aria-label="Zoom out">−</button><span class="zoom-label">{{Math.round(zoom*100)}}%</span><button type="button" class="button small secondary" @click="adjust(.1)" aria-label="Zoom in">+</button></div></div>
    <div v-if="!graph.nodes?.length" class="empty-table topology-empty">No topology relationships match the current filters. Clear filters, poll an SNMP device, or collect ARP from an enrolled node.</div>
    <div v-else class="topology-canvas" :style="{minHeight:`${graphEdges.height}px`}">
      <svg :viewBox="`0 0 ${width} ${graphEdges.height}`" role="img" aria-label="Network topology graph" :style="{transform:`scale(${zoom})`}">
        <g class="topology-edges"><g v-for="edge in graphEdges.edges" :key="edge.id"><line :x1="edge.from.x" :y1="edge.from.y" :x2="edge.to.x" :y2="edge.to.y" :class="`edge-${edge.kind}`"/><text v-if="edge.label" :x="(edge.from.x+edge.to.x)/2" :y="(edge.from.y+edge.to.y)/2-5" class="edge-label">{{edge.label}}</text></g></g>
        <g v-for="node in graph.nodes" :key="node.id" class="topology-node" :class="[`role-${node.role}`,{selected:selectedId===node.id,'scope-match':node.scopeMatch}]" :transform="`translate(${positions.result.get(node.id)?.x||0} ${positions.result.get(node.id)?.y||0})`" tabindex="0" @click="select(node)" @keydown.enter="select(node)"><title>{{nodeLabel(node)}}</title><rect v-if="node.role!=='host'" x="-62" y="-25" width="124" height="50" rx="10"/><circle v-else :r="node.kind==='peer'?27:25"/><text class="node-label" text-anchor="middle" y="4">{{node.label.length>20?`${node.label.slice(0,19)}…`:node.label}}</text><text class="node-role" text-anchor="middle" y="42">{{node.kind==='peer'?'Observed peer':roleLabel(node.role)}}</text></g>
      </svg>
    </div>
    <p v-if="graph.scope?.subnet||graph.scope?.switchId" class="mapping-note">Highlighted devices match {{graph.scope.subnet||'all subnets'}}{{graph.scope.switchName ? ` through ${graph.scope.switchName}` : ''}}. Connected peers remain visible for context.</p>
    <div class="topology-legend"><span v-if="graph.scope?.subnet||graph.scope?.switchId"><i class="legend-mark scope-legend"></i> Matches filter</span><span><i class="legend-mark role-host"></i> Hosts</span><span><i class="legend-mark role-switch"></i> Switches</span><span><i class="legend-mark role-router"></i> Routers</span><span><i class="legend-mark role-firewall"></i> Firewalls</span><span><i class="legend-mark role-hypervisor"></i> Hypervisors</span><span><i class="legend-line edge-link"></i> ARP / SNMP</span><span><i class="legend-line edge-traffic"></i> Traffic</span></div>
    <p v-if="graph.truncated" class="mapping-note">This view is bounded for responsive rendering. Narrow the node filter to inspect a larger topology in sections.</p>
  </section>
</template>

<style scoped>
.topology-panel{display:grid;gap:1rem}.topology-title{align-items:flex-start}.topology-title p{margin:.3rem 0 0}.topology-actions{display:flex;align-items:center;gap:.45rem;flex-wrap:wrap}.zoom-label{min-width:4ch;text-align:center;font-size:.75rem;color:var(--muted)}.topology-canvas{display:flex;align-items:center;justify-content:center;overflow:auto;border:1px solid var(--border);border-radius:10px;background:color-mix(in srgb,var(--panel) 82%,transparent);padding:1rem}.topology-canvas svg{width:100%;min-width:760px;transform-origin:center center;transition:transform .15s ease}.topology-node{cursor:pointer;outline:none}.topology-node rect,.topology-node circle{fill:var(--panel);stroke:var(--border-strong,var(--border));stroke-width:2}.topology-node .node-label{fill:var(--field-value);font-size:13px;font-weight:700}.topology-node .node-role{fill:var(--muted);font-size:10px}.topology-node.role-switch rect{fill:color-mix(in srgb,#5478c5 22%,var(--panel));stroke:#5478c5}.topology-node.role-router rect{fill:color-mix(in srgb,#9a72c4 22%,var(--panel));stroke:#9a72c4}.topology-node.role-firewall rect{fill:color-mix(in srgb,#c97761 22%,var(--panel));stroke:#c97761}.topology-node.role-hypervisor rect{fill:color-mix(in srgb,#4d9c89 22%,var(--panel));stroke:#4d9c89}.topology-node.role-peer circle{fill:color-mix(in srgb,var(--muted) 15%,var(--panel));stroke-dasharray:4 3}.topology-node.scope-match rect,.topology-node.scope-match circle{stroke:var(--green,#4d9c89);stroke-width:4}.scope-legend{border-color:var(--green,#4d9c89)!important}.topology-node.selected rect,.topology-node.selected circle{stroke:var(--accent,#3864ae);stroke-width:4}.topology-node:focus-visible rect,.topology-node:focus-visible circle{stroke:var(--accent,#3864ae);stroke-width:4}.topology-edges line{stroke:color-mix(in srgb,var(--muted) 55%,transparent);stroke-width:2}.topology-edges line.edge-traffic{stroke:var(--accent,#3864ae);stroke-width:3;opacity:.75}.edge-label{fill:var(--muted);font-size:10px;paint-order:stroke;stroke:var(--panel);stroke-width:4px;stroke-linejoin:round}.topology-legend{display:flex;gap:1rem;flex-wrap:wrap;color:var(--muted);font-size:.75rem}.topology-legend span{display:inline-flex;align-items:center;gap:.35rem}.legend-mark{width:11px;height:11px;border:2px solid var(--border-strong,var(--border));display:inline-block;border-radius:50%}.legend-mark.role-switch{background:#5478c5;border-color:#5478c5;border-radius:3px}.legend-mark.role-router{background:#9a72c4;border-color:#9a72c4;border-radius:3px}.legend-mark.role-firewall{background:#c97761;border-color:#c97761;border-radius:3px}.legend-mark.role-hypervisor{background:#4d9c89;border-color:#4d9c89;border-radius:3px}.legend-line{width:18px;border-top:3px solid var(--muted);display:inline-block}.legend-line.edge-traffic{border-color:var(--accent,#3864ae)}
</style>
