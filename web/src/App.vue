<script setup>
import {computed,ref,watch} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {session,api} from './lib/api.js'
import {activeTheme,applyTheme} from './lib/theme.js'
import NotificationCenter from './components/NotificationCenter.vue'
const route=useRoute(),router=useRouter(),menuOpen=ref(false)
const links=[['/','view-dashboard-outline','Overview'],['/inventory','server-network','Inventory'],['/policies','source-branch','Policy Studio'],['/reports','chart-box-outline','Reports'],['/logs','text-box-search-outline','Event logs'],['/identity','shield-account-outline','Identity'],['/admin','cog-outline','Administration']]
const title=computed(()=>links.find(l=>l[0]===route.path)?.[2]||'WinFire Secure')
const isEnterprise=computed(()=>activeTheme.value==='enterprise')
const enterpriseTitle=computed(()=>({'/':'Dashboard','/inventory':'Network / Assets','/policies':'Network / Policies','/reports':'Reporting','/logs':'Network / Visibility','/identity':'Identity','/admin':'Administration'})[route.path]||title.value)
watch(()=>route.meta.public,async publicPage=>{if(publicPage||!session.token)return;try{const me=await api('/auth/me');applyTheme(me.profile?.theme)}catch{}},{immediate:true})
async function logout(){try{await api('/auth/logout',{method:'POST',body:{refreshToken:session.refresh}})}catch{}session.clear();router.push('/login')}
</script>
<template>
  <router-view v-if="route.meta.public" />
  <div v-else class="shell">
    <aside class="side glass hacker-side" :class="{'side-open':menuOpen}">
      <div class="brand"><span class="brand-mark"><i class="mdi mdi-fire"></i></span><span class="brand-name">WIN<span>FIRE</span><small>SECURE CONTROL PLANE</small></span></div>
      <nav aria-label="Main navigation"><router-link v-for="link in links" :key="link[0]" :to="link[0]" @click="menuOpen=false" :title="link[2]"><i class="mdi" :class="`mdi-${link[1]}`"></i><span>{{link[2]}}</span></router-link></nav>
      <div class="side-foot"><span class="online-dot"></span> SYSTEM ONLINE <span class="version">v0.1</span></div>
    </aside>
    <aside class="enterprise-side" :class="{'side-open':menuOpen}">
      <router-link to="/" class="enterprise-brand" @click="menuOpen=false"><span class="enterprise-brand-mark"><i class="mdi mdi-shield-fire-outline"></i></span><span><strong>WINFIRE</strong><small>SECURE</small></span></router-link>
      <router-link to="/" class="enterprise-back" @click="menuOpen=false"><i class="mdi mdi-arrow-left"></i> Back to main menu</router-link>
      <nav class="enterprise-nav" aria-label="Enterprise navigation">
        <div class="enterprise-nav-group"><span class="enterprise-nav-label">WORKSPACE</span><router-link to="/" @click="menuOpen=false"><i class="mdi mdi-view-dashboard-outline"></i> Dashboard</router-link></div>
        <div class="enterprise-nav-group"><span class="enterprise-nav-label">ENTITIES</span><router-link to="/inventory" @click="menuOpen=false"><i class="mdi mdi-server-network"></i> Monitored assets</router-link><router-link to="/identity" @click="menuOpen=false"><i class="mdi mdi-account-key-outline"></i> Identity</router-link></div>
        <div class="enterprise-nav-group"><span class="enterprise-nav-label">NETWORK</span><router-link to="/policies" @click="menuOpen=false"><i class="mdi mdi-source-branch"></i> Policies</router-link><router-link to="/reports" @click="menuOpen=false"><i class="mdi mdi-chart-box-outline"></i> Reports</router-link></div>
        <div class="enterprise-nav-group"><span class="enterprise-nav-label">VISIBILITY</span><router-link to="/logs" @click="menuOpen=false"><i class="mdi mdi-eye-outline"></i> Activities</router-link></div>
      </nav>
      <div class="enterprise-side-foot"><router-link to="/admin" @click="menuOpen=false"><i class="mdi mdi-cog-outline"></i> Administration</router-link><span>WinFire Secure · v0.1</span></div>
    </aside>
    <div class="page-wrap">
      <header class="top glass"><button class="icon-button mobile-menu" @click="menuOpen=!menuOpen" aria-label="Toggle navigation"><i class="mdi mdi-menu"></i></button><div class="breadcrumb"><span>WINFIRE</span><i class="mdi mdi-chevron-right"></i><strong>{{isEnterprise?enterpriseTitle:title}}</strong></div><div class="top-right"><span class="environment"><span class="online-dot"></span> {{isEnterprise?'SYSTEM ONLINE':'CONTROL PLANE'}}</span><NotificationCenter /><span class="avatar">{{session.user?.email?.[0]?.toUpperCase()||'W'}}</span><span class="user-email">{{session.user?.email}}</span><button class="icon-button" @click="logout" title="Sign out" aria-label="Sign out"><i class="mdi mdi-logout"></i></button></div></header>
      <main><router-view /></main>
    </div>
  </div>
</template>
