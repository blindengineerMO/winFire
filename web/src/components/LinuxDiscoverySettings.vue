<script setup>
import {computed,onMounted,ref} from 'vue'
import {api} from '../services/api.js'
const props=defineProps({credentials:{type:Array,default:()=>[]}})
const settings=ref({credentialId:null,hostKeyPolicy:'accept-any',credential:null}),busy=ref(false),error=ref(''),message=ref('')
const sshCredentials=computed(()=>props.credentials.filter(item=>item.type==='ssh'))
async function load(){try{settings.value=await api('/settings/discovery-linux')}catch(error){error.value=error.message}}
async function save(){busy.value=true;error.value='';message.value='';try{settings.value=await api('/settings/discovery-linux',{method:'PATCH',body:{credentialId:settings.value.credentialId||null,hostKeyPolicy:settings.value.hostKeyPolicy}});message.value='Linux SSH discovery settings saved'}catch(cause){error.value=cause.message}finally{busy.value=false}}
onMounted(load)
</script>
<template>
  <section class="linux-settings">
    <div class="panel-title"><div><span class="eyebrow">NETWORK DISCOVERY</span><h2>Linux via SSH</h2></div><span class="status" :class="settings.credentialId?'reachable':'unknown'">{{settings.credentialId?'Configured':'Not configured'}}</span></div>
    <p class="muted">Use an SSH vault credential for discovered Linux and Unix hosts. ICMP TTL hints identify likely Linux systems; port 22 and the credential are then used to collect host details, ARP/neighbors, routes, connections, and firewall state. JIT MFA remains agent-only.</p>
    <form class="form-grid" @submit.prevent="save">
      <label>Default SSH discovery credential<select v-model="settings.credentialId"><option :value="null">Do not assign automatically</option><option v-for="credential in sshCredentials" :key="credential.id" :value="credential.id">{{credential.name}} · {{credential.username}}</option></select><small v-if="!sshCredentials.length">Add an SSH credential in Administration → Credentials first.</small></label>
      <label>Host key verification<select v-model="settings.hostKeyPolicy"><option value="accept-any">Accept host keys (lab / managed network)</option><option value="fingerprint">Require vault fingerprint</option></select><small>The vault credential can include a SHA256 host key fingerprint. No private key or password is returned to the browser.</small></label>
      <div class="form-actions"><button class="button primary" :disabled="busy">{{busy?'Saving…':'Save Linux discovery settings'}}</button></div>
    </form>
    <div v-if="error" class="error-msg">{{error}}</div><div v-if="message" class="success-msg">{{message}}</div>
    <div class="linux-capabilities"><strong>Available after SSH authentication</strong><ul><li>Linux distribution, kernel, hostname, interfaces, MAC addresses and routes</li><li>Neighbor/ARP cache and TCP connection snapshots for Mapping</li><li>UFW, nftables, firewalld and iptables status and rules</li><li>Firewall rule changes through the existing policy workflow when passwordless sudo permits it</li></ul></div>
  </section>
</template>
<style scoped>.linux-settings{display:grid;gap:1rem}.linux-settings .muted{padding:0 1rem}.linux-settings .form-grid{padding:0 1rem}.linux-settings small{display:block;color:var(--muted);margin-top:.3rem}.linux-capabilities{margin:0 1rem;padding:1rem;border:1px solid var(--border);border-radius:8px;color:var(--muted)}.linux-capabilities strong{color:var(--field-value)}.linux-capabilities ul{margin:.65rem 0 0 1rem;padding:0;line-height:1.7}</style>
