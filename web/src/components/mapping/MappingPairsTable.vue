<script setup>
defineProps({rows:{type:Array,default:()=>[]},loading:{type:Boolean,default:false},total:{type:Number,default:0},page:{type:Number,default:1},pages:{type:Number,default:1}})
defineEmits(['previous','next'])
</script>
<template>
  <div class="table-wrap">
    <table>
      <thead><tr><th>SOURCE</th><th>DESTINATION</th><th>CLASSIFICATION</th><th>PROTOCOL</th><th>PORT</th><th>CONNECTIONS</th><th>LAST SEEN</th></tr></thead>
      <tbody>
        <tr v-for="row in rows" :key="row.map_key">
          <td><strong>{{row.source_hostname||row.source_ip}}</strong><small class="mono">{{row.source_ip}}</small></td>
          <td><strong>{{row.destination_hostname||row.destination_ip}}</strong><small class="mono">{{row.destination_ip}}</small></td>
          <td><span class="status" :class="row.traffic_scope==='external'?'pending':row.traffic_scope==='host-local'?'neutral':'reachable'">{{row.traffic_class||'Unclassified'}} · {{row.traffic_scope||'Unknown'}}</span><small class="mapping-reason">{{row.traffic_service||row.classification_reason||'No analyzer detail'}}</small></td>
          <td>{{row.protocol}}</td><td class="mono">{{row.destination_port||'—'}}</td><td><strong>{{row.connection_count}}</strong></td>
          <td>{{row.last_seen_at?new Date(row.last_seen_at).toLocaleString():'—'}}</td>
        </tr>
        <tr v-if="!rows.length"><td colspan="7" class="empty-table">{{loading?'Loading network observations…':'No mapped traffic yet. Collect firewall events or rebuild the map.'}}</td></tr>
      </tbody>
    </table>
  </div>
  <div class="pagination"><span>{{total}} pair{{total===1?'':'s'}}</span><button class="button small secondary" :disabled="page<=1" @click="$emit('previous')">Previous</button><button class="button small secondary" :disabled="page>=pages" @click="$emit('next')">Next</button></div>
</template>
<style scoped>
.mapping-reason{display:block;max-width:260px;color:var(--muted);font-size:.7rem;line-height:1.25;margin-top:3px}
</style>
