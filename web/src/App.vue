<script setup>
import {computed,ref,watch} from 'vue'
import {useMediaQuery} from '@vueuse/core'
import {useRoute,useRouter} from 'vue-router'
import {session,api} from './services/api.js'
import {activeTheme,applyTheme,setLocalTheme} from './lib/theme.js'
import NotificationCenter from './components/NotificationCenter.vue'
import GlassWindow from './components/GlassWindow.vue'
const route=useRoute(),router=useRouter(),menuOpen=ref(false)
const isMobile=useMediaQuery('(max-width: 700px)')
watch(isMobile,()=>{menuOpen.value=false})
const syncLoading=ref(false)
const syncOpen=ref(false),syncState=ref({pending:[],schedules:[]}),syncAt=ref(''),syncBusy=ref(false),syncError=ref(''),syncMessage=ref('')
const links=[['/','view-dashboard-outline','Overview'],['/inventory','server-network','Inventory'],['/directory','account-group-outline','Directory'],['/policies','source-branch','Policy Studio'],['/reports','chart-box-outline','Reports'],['/logs','text-box-search-outline','Event logs'],['/internet','web','Internet'],['/ai-usage','robot-outline','AI Usage'],['/mapping','vector-link','Mapping'],['/identity','shield-account-outline','Identity'],['/admin','cog-outline','Administration']]
const title=computed(()=>links.find(l=>l[0]===route.path)?.[2]||'WinFire Secure')
const isDark=computed(()=>activeTheme.value==='dark')
const enterpriseTitle=computed(()=>({'/':'Dashboard','/inventory':'Network / Assets','/directory':'Entities / Directory','/policies':'Network / Policies','/reports':'Reporting','/logs':'Network / Visibility','/internet':'Network / Internet','/ai-usage':'Visibility / AI Usage','/mapping':'Network / Mapping','/identity':'Identity','/admin':'Administration'})[route.path]||title.value)
watch(()=>route.meta.public,async publicPage=>{if(publicPage||!session.token)return;try{const me=await api('/auth/me');applyTheme(me.profile?.theme)}catch{}},{immediate:true})
async function logout(){try{await api('/auth/logout',{method:'POST',body:{refreshToken:session.refresh}})}catch{}session.clear();router.push('/login')}
async function loadSync(){if(!session.token)return;syncLoading.value=true;syncState.value={pending:[],schedules:[]};syncError.value='';try{syncState.value=await api('/policies/sync')}catch(error){syncError.value=error.message}finally{syncLoading.value=false}}
async function openSync(){syncOpen.value=true;syncMessage.value='';await loadSync()}
async function submitSync(){syncBusy.value=true;syncError.value='';try{const result=await api('/policies/sync',{method:'POST',body:syncAt.value?{executeAt:new Date(syncAt.value).toISOString()}:{}});syncMessage.value=result.status==='scheduled'?`Sync scheduled for ${new Date(result.executeAt).toLocaleString()}`:`Sync started for ${result.results.length} node-policy pair(s); ${result.results.filter(item=>item.status==='failed').length} failed.`;syncAt.value='';await loadSync()}catch(error){syncError.value=error.message}finally{syncBusy.value=false}}
async function cancelSync(schedule){try{await api(`/policies/sync/${schedule.id}`,{method:'DELETE'});await loadSync()}catch(error){syncError.value=error.message}}
function toggleTheme(){setLocalTheme(isDark.value?'enterprise':'dark')}
</script>
<template>
  <router-view v-if="route.meta.public" />
  <div v-else class="shell" @keydown.esc="menuOpen=false">
    <aside id="main-navigation" class="enterprise-side" aria-label="Enterprise navigation" :inert="isMobile&&!menuOpen" :class="{'side-open':menuOpen}">
      <router-link to="/" class="enterprise-brand" @click="menuOpen=false"><span class="enterprise-brand-mark"><img src="/winfire-mark.png" alt=""></span><span><strong>WINFIRE</strong><small>SECURE</small></span></router-link>
      <router-link to="/" class="enterprise-back" @click="menuOpen=false"><i class="mdi mdi-arrow-left"></i> Back to main menu</router-link>
      <nav class="enterprise-nav" aria-label="Enterprise navigation">
        <div class="enterprise-nav-group"><span class="enterprise-nav-label">WORKSPACE</span><router-link to="/" @click="menuOpen=false"><i class="mdi mdi-view-dashboard-outline"></i> Dashboard</router-link></div>
        <div class="enterprise-nav-group"><span class="enterprise-nav-label">ENTITIES</span><router-link to="/inventory" @click="menuOpen=false"><i class="mdi mdi-server-network"></i> Monitored assets</router-link><router-link to="/directory" @click="menuOpen=false"><i class="mdi mdi-account-group-outline"></i> Directory</router-link><router-link to="/identity" @click="menuOpen=false"><i class="mdi mdi-account-key-outline"></i> Identity</router-link></div>
        <div class="enterprise-nav-group"><span class="enterprise-nav-label">NETWORK</span><router-link to="/policies" @click="menuOpen=false"><i class="mdi mdi-source-branch"></i> Policies</router-link><router-link to="/reports" @click="menuOpen=false"><i class="mdi mdi-chart-box-outline"></i> Reports</router-link></div>
        <div class="enterprise-nav-group"><span class="enterprise-nav-label">VISIBILITY</span><router-link to="/logs" @click="menuOpen=false"><i class="mdi mdi-eye-outline"></i> Activities</router-link><router-link to="/internet" @click="menuOpen=false"><i class="mdi mdi-web"></i> Internet</router-link><router-link to="/ai-usage" @click="menuOpen=false"><i class="mdi mdi-robot-outline"></i> AI Usage</router-link><router-link to="/mapping" @click="menuOpen=false"><i class="mdi mdi-vector-link"></i> Mapping</router-link></div>
      </nav>
      <div class="enterprise-side-foot"><router-link to="/admin" @click="menuOpen=false"><i class="mdi mdi-cog-outline"></i> Administration</router-link><span>WinFire Secure · v0.1</span></div>
    </aside>
    <button v-if="menuOpen" class="navigation-backdrop" aria-label="Close navigation" @click="menuOpen=false"></button>
    <div class="page-wrap">
      <header class="top glass"><button class="icon-button mobile-menu" @click="menuOpen=!menuOpen" aria-label="Toggle navigation" :aria-expanded="menuOpen" aria-controls="main-navigation"><i class="mdi mdi-menu"></i></button><div class="breadcrumb"><span>WINFIRE</span><i class="mdi mdi-chevron-right"></i><strong>{{enterpriseTitle}}</strong></div><div class="top-right"><button v-if="['owner','admin'].includes(session.user?.role)" class="button small secondary top-sync-button" @click="openSync" title="Review and deploy pending policy changes"><i class="mdi mdi-sync"></i><span>Sync policies</span></button><button class="icon-button theme-toggle" @click="toggleTheme" :title="isDark?'Switch to light theme':'Switch to dark theme'" :aria-label="isDark?'Switch to light theme':'Switch to dark theme'"><i class="mdi" :class="isDark?'mdi-white-balance-sunny':'mdi-weather-night'"></i></button><span class="environment"><span class="online-dot"></span> SYSTEM ONLINE</span><NotificationCenter /><span class="avatar">{{session.user?.email?.[0]?.toUpperCase()||'W'}}</span><span class="user-email">{{session.user?.email}}</span><button class="icon-button" @click="logout" title="Sign out" aria-label="Sign out"><i class="mdi mdi-logout"></i></button></div></header>
      <main><router-view /></main>
    </div>
    <GlassWindow v-model="syncOpen" title="Sync policies" width="650px"><div class="policy-sync-window"><p>Saved policy changes stay staged until an administrator starts or schedules a sync. Nodes in active learning are handled by their training schedule.</p><div v-if="syncError" class="error-msg">{{syncError}}</div><div v-if="syncMessage" class="success-msg">{{syncMessage}}</div><p v-if="syncLoading" role="status">Loading pending policy changes…</p><h3 v-else-if="!syncError">{{syncState.pending.length}} pending node-policy updates</h3><div class="sync-pending-list"><div v-for="pair in syncState.pending" :key="`${pair.node_id}:${pair.policy_id}`"><strong>{{pair.hostname}}</strong><span>{{pair.policy_name}}</span></div><p v-if="!syncLoading&&!syncError&&!syncState.pending.length">Everything is up to date.</p></div><h3>Scheduled syncs</h3><div v-for="schedule in syncState.schedules" :key="schedule.id" class="history-row"><span>{{new Date(schedule.execute_at).toLocaleString()}} · {{schedule.status}}</span><button v-if="schedule.status==='scheduled'" class="button small secondary" @click="cancelSync(schedule)">Cancel</button></div><label class="sync-schedule-label">Run at a change time (leave empty for now)<input v-model="syncAt" type="datetime-local"></label><div class="form-actions"><button class="button primary" :disabled="syncBusy||syncLoading||!!syncError||!syncState.pending.length" @click="submitSync">{{syncBusy?'Starting…':syncAt?'Schedule sync':'Sync now'}}</button></div></div></GlassWindow>
  </div>
</template>
