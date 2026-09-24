<script setup>
import {computed,defineAsyncComponent,ref} from 'vue'
import {useRoute,useRouter} from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
const route=useRoute(),router=useRouter(),panel=ref(null)
const tabs=[['browser','Browser activity'],['connections','Internet connections'],['devices','Browser devices'],['policies','Internet Policy Studio']]
const components={browser:defineAsyncComponent(()=>import('../components/internet/InternetBrowserActivity.vue')),connections:defineAsyncComponent(()=>import('../components/internet/InternetConnections.vue')),devices:defineAsyncComponent(()=>import('../components/internet/InternetBrowserDevices.vue')),policies:defineAsyncComponent(()=>import('../components/internet/InternetPolicies.vue'))}
const active=computed(()=>tabs.some(t=>t[0]===route.query.tab)?route.query.tab:'browser')
</script>
<template><div class="view internet-view"><PageHeader title="Internet"><button class="button secondary" @click="panel?.refresh()"><i class="mdi mdi-refresh"></i> Refresh</button></PageHeader><nav class="view-tabs" aria-label="Internet sections"><button v-for="[id,label] in tabs" :key="id" type="button" :class="{active:active===id}" :aria-current="active===id?'page':undefined" @click="router.replace({query:{...route.query,tab:id}})">{{label}}</button></nav><KeepAlive><component :is="components[active]" ref="panel" /></KeepAlive></div></template>
<style scoped>
.internet-view{min-width:0}.view-tabs{display:flex;gap:.35rem;margin:.2rem 0 1rem;border-bottom:1px solid var(--border);overflow:auto}.view-tabs button{border:0;background:transparent;color:var(--muted);padding:.7rem 1rem;font:inherit;font-weight:700;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap}.view-tabs button.active{color:var(--field-value);border-bottom-color:var(--accent,#3864ae);background:color-mix(in srgb,var(--accent,#3864ae) 8%,transparent)}
</style>
