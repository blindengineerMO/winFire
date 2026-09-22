<script setup>
defineProps({talkers:{type:Array,default:()=>[]}})
</script>
<template>
  <section class="panel glass top-talkers-panel">
    <div class="panel-title"><div><span class="eyebrow">TOP TALKERS</span><h2>Most active nodes</h2></div><span class="count-chip">{{talkers.length}} shown</span></div>
    <div class="table-wrap">
      <table><thead><tr><th>RANK</th><th>NODE</th><th>CONNECTIONS</th><th>SHARE</th></tr></thead>
        <tbody>
          <tr v-for="(talker,index) in talkers" :key="`${talker.node_id||talker.hostname}-${index}`"><td>{{index+1}}</td><td><strong>{{talker.hostname||'External peer'}}</strong></td><td><strong>{{talker.connections}}</strong></td><td><div class="talker-bar"><span :style="{width:`${Math.min(100,((talker.connections/(talkers[0]?.connections||1))*100))}%`}"></span></div></td></tr>
          <tr v-if="!talkers.length"><td colspan="4" class="empty-table">No talkers yet. Collect firewall events or rebuild the map.</td></tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
