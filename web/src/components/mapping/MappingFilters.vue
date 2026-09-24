<script setup>
const props=defineProps({nodes:{type:Array,default:()=>[]},switches:{type:Array,default:()=>[]},subnets:{type:Array,default:()=>[]},modelValue:{type:Object,required:true},busy:{type:Boolean,default:false}})
const emit=defineEmits(['update:modelValue','apply','reset'])
function update(key,value){emit('update:modelValue',{...props.modelValue,[key]:value})}
</script>
<template>
  <form class="panel glass mapping-filters" aria-label="Mapping filters" @submit.prevent="emit('apply')">
    <div class="filter-fields">
      <label>Node<select :value="modelValue.nodeId" aria-label="Filter by node" @change="update('nodeId',$event.target.value)"><option value="">All nodes</option><option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select></label>
      <label>Subnet<input :value="modelValue.subnet" list="mapping-subnets" placeholder="All subnets · enter CIDR" aria-label="Filter by subnet" @input="update('subnet',$event.target.value)"><datalist id="mapping-subnets"><option v-for="subnet in subnets" :key="subnet" :value="subnet" /></datalist></label>
      <label>Switch<select :value="modelValue.switchId" aria-label="Filter by switch" @change="update('switchId',$event.target.value)"><option value="">All switches</option><option v-for="item in switches" :key="item.id" :value="item.id">{{item.hostname}}{{item.ip ? ` · ${item.ip}` : ''}}</option></select></label>
      <label>Traffic scope<select :value="modelValue.external" aria-label="Filter traffic scope" @change="update('external',$event.target.value)"><option value="">Internal and external</option><option value="0">Internal only</option><option value="1">External only</option></select></label>
      <label>Traffic type<select :value="modelValue.trafficClass" aria-label="Filter traffic classification" @change="update('trafficClass',$event.target.value)"><option value="">All traffic types</option><option value="node-to-node">Node to node</option><option value="private">Private unicast</option><option value="multicast">Multicast</option><option value="broadcast">Broadcast</option><option value="link-local">Link local</option><option value="loopback">Loopback</option><option value="public-unicast">Public unicast</option><option value="special-purpose">Special purpose</option></select></label>
      <label>From<input :value="modelValue.from" type="datetime-local" aria-label="Mapping from date" @input="update('from',$event.target.value)"></label>
      <label>To<input :value="modelValue.to" type="datetime-local" aria-label="Mapping to date" @input="update('to',$event.target.value)"></label>
    </div>
    <div class="filter-footer"><p class="muted">Subnet and switch filters include matching devices and their peers. Switch membership uses observed ARP and forwarding tables; it does not prove physical attachment. Traffic scope and type apply to connections; neighbor links use node, subnet, switch, and dates.</p><div class="inline-actions"><button type="button" class="button secondary" :disabled="busy" @click="emit('reset')">Clear filters</button><button class="button primary" :disabled="busy">Apply filters</button></div></div>
  </form>
</template>
<style scoped>
.mapping-filters{padding:1rem;margin-bottom:1rem;display:grid;gap:.8rem}.filter-fields{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,210px),1fr));gap:.75rem}.filter-fields label{display:grid;gap:.3rem;font-size:.75rem;min-width:0}.filter-fields input,.filter-fields select{width:100%;min-width:0;box-sizing:border-box}.filter-footer{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}.filter-footer p{font-size:.75rem;max-width:85ch;margin:0}.filter-footer .inline-actions{flex-wrap:wrap}
</style>
