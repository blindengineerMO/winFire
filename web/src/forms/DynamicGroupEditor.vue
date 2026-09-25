<script setup>
import {ref,watch} from 'vue'

const props=defineProps({modelValue:{type:Object,default:()=>({enabled:false,match:'all',rules:[]})},disabled:{type:Boolean,default:false},showEnable:{type:Boolean,default:true}})
const emit=defineEmits(['update:modelValue'])
const draft=ref({enabled:false,match:'all',rules:[]}),newRule=ref({field:'hostname',operator:'contains',value:''})
function clone(value){return {enabled:value?.enabled===true,match:value?.match==='any'?'any':'all',rules:(value?.rules||[]).map(rule=>({...rule}))}}
watch(()=>props.modelValue,value=>{draft.value=clone(value)},{deep:true,immediate:true})
function publish(){emit('update:modelValue',clone(draft.value))}
function addRule(){const value=newRule.value.value.trim();if(!value)return;draft.value.rules.push({...newRule.value,value});newRule.value={field:'hostname',operator:'contains',value:''};publish()}
function removeRule(index){draft.value.rules.splice(index,1);publish()}
function update(){publish()}
function normalizeOperator(){if(newRule.value.field!=='ip'&&newRule.value.operator==='cidr')newRule.value.operator='contains'}
</script>
<template>
  <section class="dynamic-group-editor">
    <div class="dynamic-group-heading"><div><span class="eyebrow">DYNAMIC MEMBERSHIP</span><h3>Update group from node attributes</h3></div><button v-if="showEnable" type="button" class="toggle-switch" :class="{active:draft.enabled}" role="switch" :aria-checked="draft.enabled" :disabled="disabled" @click="draft.enabled=!draft.enabled;update()"><span class="toggle-track"><span></span></span><span>Enable rules</span></button><span v-else class="status reachable">Rules enabled</span></div>
    <p class="muted">Matching nodes are added automatically. Nodes that stop matching are removed on the next refresh. Use all conditions for an intersection or any condition for a union.</p>
    <div class="dynamic-rule-toolbar" :class="{disabled:disabled||!draft.enabled}">
      <label>Match<select v-model="draft.match" :disabled="disabled||!draft.enabled" @change="update"><option value="all">All conditions</option><option value="any">Any condition</option></select></label>
      <label>Field<select v-model="newRule.field" :disabled="disabled||!draft.enabled" @change="normalizeOperator"><option value="hostname">Name / hostname</option><option value="fqdn">FQDN</option><option value="ip">IP address</option><option value="application">Application</option><option value="environment">Environment</option><option value="workload_role">Workload role</option><option value="business_owner">Business owner</option><option value="criticality">Criticality</option></select></label>
      <label>Operator<select v-model="newRule.operator" :disabled="disabled||!draft.enabled"><option value="contains">Contains</option><option value="equals">Equals</option><option value="cidr">CIDR matches</option></select></label>
      <label class="dynamic-value">Value<input v-model.trim="newRule.value" :disabled="disabled||!draft.enabled" :placeholder="newRule.operator==='cidr'?'10.0.0.0/8':'server or address'" @keyup.enter.prevent="addRule"></label>
      <button type="button" class="button small secondary" :disabled="disabled||!draft.enabled||!newRule.value.trim()" @click="addRule"><i class="mdi mdi-plus"></i> Add condition</button>
    </div>
    <div v-if="draft.rules.length" class="dynamic-rule-list"><div v-for="(rule,index) in draft.rules" :key="`${rule.field}-${rule.operator}-${rule.value}-${index}`" class="dynamic-rule"><span class="status reachable">{{rule.field}}</span><strong>{{rule.operator}}</strong><code>{{rule.value}}</code><button type="button" class="icon-button" :disabled="disabled" :aria-label="`Remove condition ${index+1}`" @click="removeRule(index)"><i class="mdi mdi-close"></i></button></div></div>
    <p v-else class="empty-side">No conditions configured. Enable rules and add a hostname, FQDN, IP, CIDR, or application metadata condition.</p>
  </section>
</template>
<style scoped>
.dynamic-group-editor{display:grid;gap:.75rem;padding:1rem;border:1px solid var(--border);border-radius:9px;background:color-mix(in srgb,var(--panel) 70%,transparent)}.dynamic-group-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem}.dynamic-group-heading h3{margin:.2rem 0 0}.toggle-switch{display:inline-flex;align-items:center;gap:.5rem;border:0;background:transparent;color:var(--field-value);font:inherit;font-size:.72rem;font-weight:700;white-space:nowrap;padding:0}.toggle-track{width:34px;height:19px;padding:2px;border-radius:999px;background:var(--border);transition:.15s}.toggle-track span{display:block;width:15px;height:15px;border-radius:50%;background:var(--muted);transition:.15s}.toggle-switch.active .toggle-track{background:var(--green)}.toggle-switch.active .toggle-track span{transform:translateX(15px);background:#06231f}.toggle-switch:focus-visible{outline:2px solid var(--green);outline-offset:3px}.toggle-switch:disabled{opacity:.55;cursor:not-allowed}.dynamic-rule-toolbar{display:grid;grid-template-columns:1fr 1.2fr 1.1fr 2fr auto;gap:.6rem;align-items:end}.dynamic-rule-toolbar label{display:grid;gap:.3rem;font-size:.72rem;font-weight:700}.dynamic-rule-toolbar input,.dynamic-rule-toolbar select{min-width:0}.dynamic-rule-toolbar.disabled{opacity:.6}.dynamic-rule-list{display:grid;gap:.4rem}.dynamic-rule{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap;padding:.5rem .65rem;border:1px solid var(--border);border-radius:7px}.dynamic-rule code{overflow-wrap:anywhere;color:var(--field-value)}.dynamic-rule .icon-button{margin-left:auto}@media(max-width:800px){.dynamic-rule-toolbar{grid-template-columns:repeat(2,minmax(0,1fr))}.dynamic-rule-toolbar .dynamic-value{grid-column:span 2}.dynamic-rule-toolbar button{grid-column:span 2}}
</style>
