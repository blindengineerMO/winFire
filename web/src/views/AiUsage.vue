<script setup>
import {computed} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import AiUsageTable from '../components/ai/AiUsageTable.vue'
import AiAdmin from '../components/ai/AiAdmin.vue'
const route=useRoute(),router=useRouter(),tabs=[['usage','Reported usage'],['observations','Observed AI traffic'],['reporters','Reporters / coverage']]
const active=computed(()=>tabs.some(t=>t[0]===route.query.tab)?route.query.tab:'usage')
function select(tab){const query={...route.query,tab,page:undefined,detail:undefined};for(const key of ['outcome','category','confidence','sort','order'])delete query[key];router.replace({query})}
</script>
<template><div class="view ai-view"><nav class="view-tabs" aria-label="AI usage sections"><button v-for="[id,label] in tabs" :key="id" :class="{active:active===id}" :aria-current="active===id?'page':undefined" @click="select(id)">{{label}}</button></nav><AiAdmin v-if="active==='reporters'"/><AiUsageTable v-else :kind="active"/></div></template>
<style scoped src="../components/ai/ai.css"></style>
<style scoped>.ai-view{min-width:0;max-width:100%;display:grid;gap:1rem}</style>
