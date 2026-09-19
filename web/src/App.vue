<script setup>
import {computed,ref} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import {session,api} from './lib/api.js'
const route=useRoute(),router=useRouter(),menuOpen=ref(false)
const links=[['/','view-dashboard-outline','Overview'],['/inventory','server-network','Inventory'],['/policies','source-branch','Policy Studio'],['/reports','chart-box-outline','Reports'],['/logs','text-box-search-outline','Event logs'],['/identity','shield-account-outline','Identity'],['/admin','cog-outline','Administration']]
const title=computed(()=>links.find(l=>l[0]===route.path)?.[2]||'WinFire Secure')
async function logout(){try{await api('/auth/logout',{method:'POST',body:{refreshToken:session.refresh}})}catch{}session.clear();router.push('/login')}
</script>
<template>
  <router-view v-if="route.meta.public" />
  <div v-else class="shell">
    <aside class="side glass" :class="{'side-open':menuOpen}">
      <div class="brand"><span class="brand-mark"><i class="mdi mdi-fire"></i></span><span class="brand-name">WIN<span>FIRE</span><small>SECURE CONTROL PLANE</small></span></div>
      <nav aria-label="Main navigation"><router-link v-for="link in links" :key="link[0]" :to="link[0]" @click="menuOpen=false" :title="link[2]"><i class="mdi" :class="`mdi-${link[1]}`"></i><span>{{link[2]}}</span></router-link></nav>
      <div class="side-foot"><span class="online-dot"></span> SYSTEM ONLINE <span class="version">v0.1</span></div>
    </aside>
    <div class="page-wrap">
      <header class="top glass"><button class="icon-button mobile-menu" @click="menuOpen=!menuOpen" aria-label="Toggle navigation"><i class="mdi mdi-menu"></i></button><div class="breadcrumb"><span>WINFIRE</span><i class="mdi mdi-chevron-right"></i><strong>{{title}}</strong></div><div class="top-right"><span class="environment"><span class="online-dot"></span> CONTROL PLANE</span><span class="avatar">{{session.user?.email?.[0]?.toUpperCase()||'W'}}</span><span class="user-email">{{session.user?.email}}</span><button class="icon-button" @click="logout" title="Sign out" aria-label="Sign out"><i class="mdi mdi-logout"></i></button></div></header>
      <main><router-view /></main>
    </div>
  </div>
</template>
