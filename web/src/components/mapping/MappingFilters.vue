<script setup>
defineProps({nodes:{type:Array,default:()=>[]},nodeId:{type:String,default:''},external:{type:String,default:''},trafficClass:{type:String,default:''}})
const emit=defineEmits(['update:nodeId','update:external','update:trafficClass','change'])
function change(){emit('change')}
</script>
<template>
  <div class="table-tools">
    <select :value="nodeId" aria-label="Filter by node" @change="emit('update:nodeId',$event.target.value);change()">
      <option value="">All nodes</option>
      <option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option>
    </select>
    <select :value="external" aria-label="Filter traffic scope" @change="emit('update:external',$event.target.value);change()">
      <option value="">Internal and external</option>
      <option value="0">Internal only</option>
      <option value="1">External only</option>
    </select>
    <select :value="trafficClass" aria-label="Filter traffic classification" @change="emit('update:trafficClass',$event.target.value);change()">
      <option value="">All traffic types</option>
      <option value="node-to-node">Node to node</option>
      <option value="private">Private unicast</option>
      <option value="multicast">Multicast</option>
      <option value="broadcast">Broadcast</option>
      <option value="link-local">Link local</option>
      <option value="loopback">Loopback</option>
      <option value="public-unicast">Public unicast</option>
      <option value="special-purpose">Special purpose</option>
    </select>
  </div>
</template>
