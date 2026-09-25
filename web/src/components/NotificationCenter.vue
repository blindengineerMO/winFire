<script setup>
import {onMounted,onUnmounted,ref} from 'vue'
import {useRouter} from 'vue-router'
import {api,session} from '../services/api.js'

const router=useRouter(),open=ref(false),items=ref([]),unread=ref(0),error=ref('')
let timer
const destinations={ddos_attack:'/logs?tab=ddos',security_policy:'/admin?tab=notifications&notificationTab=automations',policy_drift:'/reports',verifier_failure:'/reports',mfa_access_request:'/identity',mfa_challenge_failure:'/identity',agent_offline:'/inventory',node_unreachable:'/inventory'}
async function load(){if(!session.token)return;try{const result=await api('/notifications');items.value=result.items;unread.value=result.unread;error.value=''}catch(cause){error.value=cause.message}}
async function show(){open.value=!open.value;if(open.value)await load()}
async function read(item){try{if(!item.read_at){await api(`/notifications/${item.id}/read`,{method:'PATCH',body:{}});item.read_at=new Date().toISOString();unread.value=Math.max(0,unread.value-1)}open.value=false;router.push(destinations[item.category]||'/')}catch(cause){error.value=cause.message}}
async function readAll(){try{const result=await api('/notifications/read-all',{method:'POST',body:{}});items.value=result.items;unread.value=result.unread}catch(cause){error.value=cause.message}}
function outside(event){if(!event.target.closest('.notification-center'))open.value=false}
onMounted(()=>{load();timer=setInterval(load,30_000);document.addEventListener('click',outside)})
onUnmounted(()=>{clearInterval(timer);document.removeEventListener('click',outside)})
</script>
<template>
  <div class="notification-center">
    <button class="icon-button notification-trigger" :aria-label="`Notifications, ${unread} unread`" :aria-expanded="open" title="Notifications" @click="show"><i class="mdi mdi-bell-outline"></i><span v-if="unread" class="notification-count">{{unread>99?'99+':unread}}</span></button>
    <div v-if="open" class="notification-popover" role="region" aria-label="Notifications">
      <div class="notification-popover-head"><strong>Notifications</strong><button v-if="unread" type="button" @click="readAll">Mark all read</button></div>
      <div v-if="error" class="error-msg">{{error}}</div>
      <div v-if="!items.length" class="notification-empty">No notifications yet.</div>
      <button v-for="item in items" :key="item.id" class="notification-item" :class="{unread:!item.read_at}" @click="read(item)"><span class="notification-item-title">{{item.title}}</span><span>{{item.body}}</span><time>{{new Date(item.created_at).toLocaleString()}}</time></button>
    </div>
  </div>
</template>
