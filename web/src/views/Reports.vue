<script setup>
import {onMounted,ref,computed} from 'vue'
import PageHeader from '../components/PageHeader.vue'
import {api,download,session} from '../lib/api.js'
const tab=ref('coverage'),rows=ref([]),search=ref(''),error=ref(''),message=ref(''),busy=ref(false)
const canEdit=computed(()=>['owner','admin','editor'].includes(session.user?.role))
const filtered=computed(()=>rows.value.filter(row=>JSON.stringify(row).toLowerCase().includes(search.value.toLowerCase())))
const columns=computed(()=>Object.keys(filtered.value[0]||rows.value[0]||{}))
async function load(){busy.value=true;try{rows.value=await api(`/reports/${tab.value}`);error.value=''}catch(e){error.value=e.message}finally{busy.value=false}}
async function exportFile(format){try{await download(`/reports/${tab.value}?export=${format}`,`${tab.value}.${format}`)}catch(e){error.value=e.message}}
async function checkDrift(){busy.value=true;error.value='';try{const result=await api('/drift/checks',{method:'POST',body:{}});message.value=`Checked ${result.checks.length} assigned policy/node pairs`;await load()}catch(e){error.value=e.message}finally{busy.value=false}}
onMounted(load)
</script>
<template><div class="view"><PageHeader eyebrow="ANALYTICS / COMPLIANCE" title="Reports" description="Coverage, inventory and verification evidence"><button v-if="canEdit&&tab==='coverage'" class="button secondary" :disabled="busy" @click="checkDrift"><i class="mdi mdi-radar"></i> Check drift</button><button class="button secondary" @click="exportFile('csv')"><i class="mdi mdi-file-delimited-outline"></i> CSV</button><button class="button primary" @click="exportFile('pdf')"><i class="mdi mdi-file-pdf-box"></i> PDF</button></PageHeader><div v-if="error" class="error-msg">{{error}}</div><div v-if="message" class="success-msg">{{message}}</div><section class="panel glass"><div class="tab-bar"><button v-for="name in ['coverage','inventory','dns','compliance','verification']" :key="name" :class="{active:tab===name}" @click="tab=name;load()">{{name}}</button></div><div class="panel-title"><div><span class="eyebrow">{{tab.toUpperCase()}} REPORT</span><h2>{{rows.length}} records</h2></div><input v-model="search" class="search" placeholder="Filter report" aria-label="Filter report"></div><div class="table-wrap"><table><thead><tr><th v-for="column in columns" :key="column">{{column.replaceAll('_',' ').toUpperCase()}}</th></tr></thead><tbody><tr v-for="(row,index) in filtered" :key="index"><td v-for="column in columns" :key="column">{{row[column]??'—'}}</td></tr><tr v-if="!filtered.length"><td :colspan="columns.length||1" class="empty-table">{{busy?'Loading report…':'No matching records.'}}</td></tr></tbody></table></div></section></div></template>
