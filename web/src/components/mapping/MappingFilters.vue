<script setup>
defineProps({nodes:{type:Array,default:()=>[]},nodeId:{type:String,default:''},external:{type:String,default:''}})
const emit=defineEmits(['update:nodeId','update:external','change'])
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
  </div>
</template>
