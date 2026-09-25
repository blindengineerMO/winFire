<script setup>
import {ref,watch} from 'vue'
import {api} from '../services/api.js'
const props=defineProps({sourceId:{type:String,required:true}})
const history=ref({items:[],total:0}),page=ref(1),busy=ref(false),error=ref('')
let request=0
async function load(){
  const revision=++request;busy.value=true;error.value=''
  try{const result=await api(`/discovery/azure/resources/${props.sourceId}/history?page=${page.value}&pageSize=25`);if(revision===request)history.value=result}
  catch(e){if(revision===request)error.value=e.message}
  finally{if(revision===request)busy.value=false}
}
watch(()=>props.sourceId,()=>{page.value=1;history.value={items:[],total:0};load()},{immediate:true})
</script>
<template>
  <section class="source-history" aria-label="Source history">
    <h3>Identity and change history</h3>
    <p v-if="error" class="error-msg" role="alert">{{error}} <button type="button" class="button secondary" @click="load">Retry</button></p>
    <p v-if="busy" role="status">Loading history…</p>
    <ol v-else>
      <li v-for="entry in history.items" :key="entry.id">
        <strong>{{entry.change==='resolution'?'Operator decision':entry.change}}</strong>
        <time>{{new Date(entry.at).toLocaleString()}}</time>
        <p>{{entry.after.reason||entry.after.action||'Provider lifecycle updated'}}<span v-if="entry.after.completeMisses"> · {{entry.after.completeMisses}} complete scans without this resource</span></p>
        <small v-if="entry.after.nodeId">Linked asset: {{entry.after.nodeId}}</small>
        <small v-if="entry.after.previousNodeId">Previous asset: {{entry.after.previousNodeId}}</small>
        <details><summary>Recorded evidence</summary><pre>{{JSON.stringify({before:entry.before,after:entry.after},null,2)}}</pre></details>
      </li>
    </ol>
    <p v-if="!busy&&!error&&!history.total">No changes recorded.</p>
    <div v-if="history.total" class="history-pages"><span>{{history.total}} changes · page {{page}}</span><button type="button" class="button secondary" :disabled="busy||page===1" @click="page--;load()">Previous</button><button type="button" class="button secondary" :disabled="busy||page*25>=history.total" @click="page++;load()">Next</button></div>
  </section>
</template>
<style scoped>
.source-history{margin-block:16px;min-width:0}ol{list-style:none;padding:0}li{border-left:2px solid var(--border);padding:8px 12px;margin-block:8px;overflow-wrap:anywhere}time,small{display:block;color:var(--muted)}p{margin-block:6px}pre{max-height:240px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}summary{cursor:pointer}.history-pages{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
</style>
