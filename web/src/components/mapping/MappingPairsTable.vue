<script setup>
defineProps({rows:{type:Array,default:()=>[]},loading:{type:Boolean,default:false},total:{type:Number,default:0},page:{type:Number,default:1},pages:{type:Number,default:1}})
const emit=defineEmits(['previous','next','select'])
const hasDistinctAddress=(name,address)=>Boolean(name&&address&&String(name).toLowerCase()!==String(address).toLowerCase())
const serviceLabel=value=>String(value||'Unidentified').split(/\r?\n/,1)[0].trim()||'Unidentified'
const serviceDetails=row=>[row.traffic_service,row.classification_reason].filter(Boolean).join(' — ')||'Service could not be identified from the observed traffic'
</script>
<template>
  <div class="table-wrap">
    <table>
      <thead><tr><th>SOURCE</th><th>DESTINATION</th><th>CLASSIFICATION</th><th>PROTOCOL</th><th>PORT</th><th>CONNECTIONS</th><th>LAST SEEN</th></tr></thead>
      <tbody>
        <tr v-for="row in rows" :key="row.map_key" class="mapping-row" tabindex="0" @click="emit('select',row)" @keydown.enter="emit('select',row)">
          <td class="mapping-endpoint"><strong>{{row.source_hostname||row.source_ip||'—'}}</strong><small v-if="hasDistinctAddress(row.source_hostname,row.source_ip)" class="mono">{{row.source_ip}}</small></td>
          <td class="mapping-endpoint"><strong>{{row.destination_hostname||row.destination_ip||'—'}}</strong><small v-if="hasDistinctAddress(row.destination_hostname,row.destination_ip)" class="mono">{{row.destination_ip}}</small></td>
          <td><span class="status" :class="row.traffic_scope==='external'?'pending':row.traffic_scope==='host-local'?'neutral':'reachable'">{{row.traffic_class||'Unclassified'}} · {{row.traffic_scope||'Unknown'}}</span><strong class="mapping-service" :title="serviceDetails(row)" :aria-label="serviceDetails(row)">{{serviceLabel(row.traffic_service)}}</strong></td>
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
.mapping-endpoint{min-width:180px;white-space:normal;vertical-align:top}.mapping-endpoint strong,.mapping-endpoint small{display:block;overflow-wrap:anywhere}.mapping-endpoint small{margin-top:4px;color:var(--muted)}.mapping-service{display:block;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.7rem;line-height:1.25;margin-top:3px;cursor:help}
</style>
