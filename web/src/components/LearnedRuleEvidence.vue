<script setup>
defineProps({evidence:{type:Object,required:true}})
const formatTime=value=>value?new Date(value).toLocaleString():'Unknown'
</script>

<template>
  <details class="learned-evidence">
    <summary>{{evidence.eventCount}} observed {{evidence.eventCount===1?'event':'events'}} · {{evidence.sourcePortCount}} source {{evidence.sourcePortCount===1?'port':'ports'}}</summary>
    <div class="evidence-body">
      <div v-for="(flow,index) in evidence.samples||[evidence.sample]" :key="index"><span>{{index===0?'Sample flows':''}}</span><code>{{flow.protocol}} {{flow.sourceIp}}:{{flow.sourcePort??'—'}} → {{flow.destinationIp}}:{{flow.destinationPort}} <template v-if="flow.eventCount">({{flow.eventCount}} {{flow.eventCount===1?'event':'events'}})</template></code></div>
      <div v-if="evidence.sample.program"><span>Program</span><code>{{evidence.sample.program}}</code></div>
      <div v-if="evidence.unresolvedProgram"><span>Scope</span><span class="scope-warning">An observed program path could not be mapped. This proposal allows any program for this traffic.</span></div>
      <div><span>Observed</span><span>{{formatTime(evidence.firstSeenAt)}} to {{formatTime(evidence.lastSeenAt)}}</span></div>
    </div>
  </details>
</template>

<style scoped>
.learned-evidence{width:100%;min-width:0;margin-top:.4rem;border-top:1px solid var(--border);padding-top:.45rem;font-size:.7rem}
summary{cursor:pointer;color:var(--muted);font-weight:600;list-style:revert}
summary:hover{color:var(--text)}
.evidence-body{display:grid;gap:.4rem;margin:.55rem 0 .2rem}
.evidence-body>div{display:grid;grid-template-columns:75px minmax(0,1fr);gap:.5rem;align-items:start}
.evidence-body span:first-child{color:var(--muted)}
code{overflow-wrap:anywhere;white-space:normal;color:var(--text);font-size:.68rem}
.scope-warning{color:#9b4c15}
@media(max-width:560px){.evidence-body>div{grid-template-columns:1fr;gap:.15rem}}
</style>
