<script setup>
import {computed,ref} from 'vue'
import {api} from '../lib/api.js'

const props=defineProps({nodes:{type:Array,required:true},agents:{type:Array,required:true}})
const selected=ref([]),issued=ref(null),busy=ref(false),error=ref('')
const enrolledIds=computed(()=>new Set(props.agents.map(agent=>agent.node_id)))
const eligible=computed(()=>props.nodes.filter(node=>!enrolledIds.value.has(node.id)))
const bootstrapCommand=computed(()=>location.protocol==='https:'?`irm ${location.origin}/api/v1/agent-package/enroll.ps1 | iex`:null)
function toggle(nodeId){selected.value=selected.value.includes(nodeId)?selected.value.filter(id=>id!==nodeId):[...selected.value,nodeId]}
function selectFirstPage(){selected.value=eligible.value.slice(0,50).map(node=>node.id)}
async function generate(){
  busy.value=true;error.value='';issued.value=null
  try{
    issued.value=await api('/agents/enrollment-tokens/bulk',{method:'POST',body:{nodeIds:selected.value}})
    selected.value=[]
  }catch(e){error.value=e.message}
  finally{busy.value=false}
}
function downloadTokens(){
  if(!issued.value)return
  const blob=new Blob([JSON.stringify({expiresAt:issued.value.expiresAt,tokens:issued.value.tokens},null,2)],{type:'application/json'})
  const link=document.createElement('a'),url=URL.createObjectURL(blob)
  link.href=url;link.download='winfire-agent-enrollment-tokens.json';link.click()
  setTimeout(()=>URL.revokeObjectURL(url),1000)
}
</script>

<template>
  <details class="bulk-enrollment">
    <summary>Bulk agent enrollment</summary>
    <p>Select up to 50 nodes. Tokens are shown once and expire after 15 minutes. Install the signed agent executable on each matching node and enter its token when prompted.</p>
    <p v-if="bootstrapCommand">On each selected Windows node, run this in elevated PowerShell. The bootstrap checks the package hash and Authenticode signature before installation.</p>
    <code v-if="bootstrapCommand" class="bootstrap-command">{{bootstrapCommand}}</code>
    <div v-if="eligible.length" class="bulk-controls">
      <button type="button" class="button small secondary" @click="selectFirstPage">Select first {{Math.min(eligible.length,50)}}</button>
      <button type="button" class="button small primary" :disabled="busy||!selected.length||selected.length>50" @click="generate">{{busy?'Generating…':`Generate ${selected.length} tokens`}}</button>
    </div>
    <div v-if="error" class="error-msg" role="alert">{{error}}</div>
    <div v-if="!eligible.length" class="muted">All listed nodes already have an agent.</div>
    <div v-else class="bulk-node-list">
      <label v-for="node in eligible" :key="node.id"><input type="checkbox" :checked="selected.includes(node.id)" :disabled="!selected.includes(node.id)&&selected.length>=50" @change="toggle(node.id)">{{node.hostname}} <small>{{node.ip||node.fqdn||''}}</small></label>
    </div>
    <div v-if="issued" class="bulk-results" aria-live="polite">
      <p><strong>{{issued.tokens.length}} tokens generated.</strong> Expires {{new Date(issued.expiresAt).toLocaleString()}}. Save these now; WinFire stores only their hashes.</p>
      <button type="button" class="button small secondary" @click="downloadTokens">Download token JSON</button>
      <div v-for="item in issued.tokens" :key="item.nodeId" class="bulk-token"><strong>{{item.hostname}}</strong><code>{{item.token}}</code></div>
    </div>
  </details>
</template>

<style scoped>
.bulk-enrollment{margin-top:1.25rem;border-top:1px solid var(--border);padding-top:1rem}
summary{cursor:pointer;font-weight:700}
.bulk-enrollment p{font-size:.85rem;color:var(--muted);line-height:1.5}
.bulk-controls{display:flex;gap:.5rem;flex-wrap:wrap;margin:.75rem 0}
.bulk-node-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.35rem;max-height:15rem;overflow:auto}
.bulk-node-list label{display:flex;align-items:center;gap:.45rem;padding:.45rem;border:1px solid var(--border);border-radius:5px;font-size:.8rem}
.bulk-node-list small{color:var(--muted)}
.bulk-results{margin-top:1rem}
.bootstrap-command{display:block;overflow-wrap:anywhere;margin:.5rem 0 1rem;padding:.7rem;border:1px solid var(--border);font-size:.8rem}
.bulk-token{display:grid;grid-template-columns:minmax(8rem,1fr) minmax(0,2fr);gap:.5rem;padding:.45rem 0;border-bottom:1px solid var(--border)}
.bulk-token code{overflow-wrap:anywhere;font-size:.75rem}
@media(max-width:620px){.bulk-token{grid-template-columns:1fr}}
</style>
