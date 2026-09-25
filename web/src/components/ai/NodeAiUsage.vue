<script setup>
import {ref,watch} from 'vue'
import {api} from '../../services/api.js'
import AiDetails from './AiDetails.vue'
const props=defineProps({nodeId:{type:String,required:true}}),data=ref(null),error=ref(''),selected=ref(''),kind=ref('usage'),open=ref(false)
let sequence=0
watch(()=>props.nodeId,async id=>{const current=++sequence;data.value=null;error.value='';try{const result=await api(`/nodes/${encodeURIComponent(id)}/ai-usage?limit=5`);if(current===sequence)data.value=result}catch(e){if(current===sequence)error.value=e.message}},{immediate:true})
function detail(row,type){selected.value=row.id;kind.value=type;open.value=true}
</script>
<template><section class="ai-section ai-card"><h3>AI usage</h3><p v-if="error" class="error-msg" role="alert">{{error}}</p><template v-if="data"><p>{{data.reported.total}} reported operations · {{data.observations.total}} traffic observations</p><p class="ai-note">Partial coverage. Unreported activity, identity and metrics remain unknown.</p><div v-for="[key,label,type] in [['reported','Recent reported operations','usage'],['observations','Recent traffic observations','observations']]" :key="key"><h4>{{label}}</h4><p v-if="!data[key].items.length" class="ai-note">None recorded for this node.</p><p v-for="row in data[key].items" :key="row.id"><button class="ai-link" @click="detail(row,type)">{{new Date(row.observed_at).toLocaleString()}} · {{row.operation||row.category}} · {{row.provider||row.hostname||'Unknown provider'}}</button></p><router-link :to="{path:'/ai-usage',query:{tab:type,nodeId}}">View all {{label.toLowerCase()}}</router-link></div></template><p v-else-if="!error">Loading AI summary…</p><AiDetails v-model="open" :id="selected" :kind="kind"/></section></template>
<style scoped src="./ai.css"></style>
