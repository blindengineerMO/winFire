<script setup>
import {computed} from 'vue'
import GlassWindow from './GlassWindow.vue'

const props=defineProps({
  modelValue:{type:Boolean,required:true},
  transaction:{type:Object,default:null},
  title:{type:String,default:'Transaction details'},
  canAllow:{type:Boolean,default:false},
  canDeny:{type:Boolean,default:false},
  canIgnore:{type:Boolean,default:false},
  loadingActions:{type:Boolean,default:false},
  busy:{type:Boolean,default:false},
})
const emit=defineEmits(['update:modelValue','allow','deny','ignore'])
const label=value=>String(value).replace(/([a-z0-9])([A-Z])/g,'$1 $2').replace(/[_-]+/g,' ').replace(/\b\w/g,character=>character.toUpperCase())
const format=value=>{
  if(value===null||value===undefined||value==='')return '—'
  if(typeof value==='object')return JSON.stringify(value,null,2)
  return String(value)
}
const entries=computed(()=>Object.entries(props.transaction||{}).filter(([key,value])=>!['node_snapshot_json','classification_json'].includes(key)&&value!==null&&value!==undefined&&value!=='').map(([key,value])=>({key,label:label(key),value:format(value)})))
</script>

<template>
  <GlassWindow :model-value="modelValue" :title="title" width="760px" @update:modelValue="emit('update:modelValue',$event)">
    <div class="transaction-details">
      <slot name="links" />
      <div v-if="transaction" class="transaction-grid">
        <div v-for="entry in entries" :key="entry.key" class="transaction-field" :class="{wide:entry.value.length>90}">
          <span>{{entry.label}}</span><code>{{entry.value}}</code>
        </div>
      </div>
      <p v-else class="empty-side">No transaction selected.</p>
      <p v-if="loadingActions" class="muted">Finding a representative firewall event for rule actions…</p>
      <div class="transaction-actions">
        <button v-if="canAllow" type="button" class="button small primary" :disabled="busy" @click="emit('allow')"><i class="mdi mdi-check-circle-outline"></i> Create allow rule</button>
        <button v-if="canDeny" type="button" class="button small danger" :disabled="busy" @click="emit('deny')"><i class="mdi mdi-cancel"></i> Create reject rule</button>
        <button v-if="canIgnore" type="button" class="button small secondary" :disabled="busy" @click="emit('ignore')"><i class="mdi mdi-filter-off-outline"></i> Ignore like traffic</button>
        <span v-if="!canAllow&&!canDeny&&!canIgnore&&!loadingActions" class="muted">No quick rules apply to this transaction.</span>
      </div>
    </div>
  </GlassWindow>
</template>

<style scoped>
.transaction-details{display:grid;gap:1rem}.transaction-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.65rem;max-height:52vh;overflow:auto;padding-right:.2rem}.transaction-field{display:grid;gap:.2rem;min-width:0;padding:.55rem .65rem;border:1px solid var(--border);border-radius:6px;background:color-mix(in srgb,var(--panel) 78%,transparent)}.transaction-field.wide{grid-column:1/-1}.transaction-field>span{font-size:.64rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:700}.transaction-field code{font-family:var(--font-mono,ui-monospace,monospace);font-size:.75rem;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--field-value)}.transaction-actions{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap;border-top:1px solid var(--border);padding-top:.85rem}@media(max-width:680px){.transaction-grid{grid-template-columns:1fr}.transaction-field.wide{grid-column:auto}}
</style>
