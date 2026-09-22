<script setup>
defineProps({entries:{type:Array,default:()=>[]},nodeSelected:{type:Boolean,default:false}})
defineEmits(['collect'])
</script>
<template>
  <section class="panel glass">
    <div class="panel-title"><div><span class="eyebrow">ARP SNAPSHOT</span><h2>Neighbor table</h2></div><button class="button small secondary" :disabled="!nodeSelected" @click="$emit('collect')"><i class="mdi mdi-download-network"></i> Collect from node</button></div>
    <div class="table-wrap"><table><thead><tr><th>NODE</th><th>IP</th><th>MAC</th><th>INTERFACE</th><th>STATE</th></tr></thead><tbody>
      <tr v-for="entry in entries.slice(0,100)" :key="entry.id"><td>{{entry.hostname}}</td><td class="mono">{{entry.ip}}</td><td class="mono">{{entry.mac||'—'}}</td><td>{{entry.interface||'—'}}</td><td>{{entry.state||'—'}}</td></tr>
      <tr v-if="!entries.length"><td colspan="5" class="empty-table">No ARP observations yet.</td></tr>
    </tbody></table></div>
  </section>
</template>
