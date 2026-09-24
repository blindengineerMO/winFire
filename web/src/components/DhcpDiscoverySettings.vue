<script setup>
import {onMounted} from 'vue'
import {useDhcpImport} from '../composables/useDhcpImport.js'
const {content,result,history,busy,error,ready,load,readFile,submit,inspect}=useDhcpImport()
const time=value=>new Date(value).toLocaleString()
onMounted(()=>load())
</script>

<template>
  <section class="dhcp-import">
    <div><span class="eyebrow">PASSIVE ENRICHMENT</span><h3>Windows DHCP lease import</h3></div>
    <p class="muted">Export current leases with <code>scripts/Export-DhcpLeases.ps1</code>, then preview the JSON below. Configure Local asset CIDRs in Server config first. No host scan or management connection is made by this import.</p>
    <form class="dhcp-form" @submit.prevent="submit(false)">
      <label>Lease export (.json)<input type="file" accept=".json,application/json" :disabled="busy" @change="readFile"></label>
      <label>Lease JSON<textarea v-model="content" rows="6" :disabled="busy" required spellcheck="false" placeholder='{"source":"dhcp.example.com","observedAt":"2026-09-24T12:00:00Z","leases":[...]}'></textarea></label>
      <small class="muted">Up to 2,000 leases per import. Active, unexpired local leases enrich inventory. Conflicting identities are left for review; managed names and verified status are preserved.</small>
      <div class="inline-actions"><button class="button secondary" :disabled="busy || !content.trim()">Preview import</button><button type="button" class="button primary" :disabled="busy || !ready" @click="submit(true)">{{busy?'Working…':'Import eligible leases'}}</button></div>
    </form>
    <p v-if="error" class="error-msg" role="alert">{{error}}</p>
    <section v-if="result" aria-live="polite">
      <h3>{{result.id?'Import report':'Preview'}} · {{result.source}}</h3>
      <p>{{result.summary.created}} new · {{result.summary.enriched}} enriched · {{result.summary.skipped}} skipped · {{result.summary.conflict}} conflicts <span v-if="!result.id">(proposed)</span></p>
      <p v-if="result.id" class="success-msg">{{result.replayed?'This export was already imported.':'Import saved.'}} No active scans were started.</p>
      <div class="table-wrap dhcp-results"><table><thead><tr><th>IP / MAC</th><th>HOSTNAME</th><th>LEASE EXPIRY</th><th>RESULT</th><th>REASON</th></tr></thead><tbody><tr v-for="row in result.rows" :key="row.row"><td>{{row.ip}}<small>{{row.mac || 'Invalid MAC'}}</small></td><td>{{row.hostname || '—'}}</td><td>{{time(row.leaseExpiry)}}</td><td><span class="status" :class="row.action==='conflict'?'failed':'pending'">{{row.action}}</span></td><td>{{row.reason}}</td></tr></tbody></table></div>
    </section>
    <section>
      <h3>Import history</h3>
      <div class="table-wrap"><table><thead><tr><th>SOURCE</th><th>OBSERVED</th><th>IMPORTED</th><th>RESULTS</th><th></th></tr></thead><tbody><tr v-for="item in history.items" :key="item.id"><td>{{item.source}}</td><td>{{time(item.observedAt)}}</td><td>{{time(item.importedAt)}}</td><td>{{item.summary.created}} new · {{item.summary.enriched}} enriched · {{item.summary.conflict}} conflicts</td><td><button class="button small secondary" :disabled="busy" @click="inspect(item.id)">View report</button></td></tr><tr v-if="!history.items.length"><td colspan="5" class="empty-table">No DHCP leases imported yet.</td></tr></tbody></table></div>
      <div class="inline-actions"><button class="button small secondary" :disabled="busy || history.page<=1" @click="load(history.page-1)">Previous</button><span>Page {{history.page}} of {{history.totalPages}}</span><button class="button small secondary" :disabled="busy || history.page>=history.totalPages" @click="load(history.page+1)">Next</button></div>
    </section>
  </section>
</template>

<style scoped>
.dhcp-import,.dhcp-form{display:grid;gap:1rem;min-width:0}.dhcp-import{padding:1rem;box-sizing:border-box;max-width:100%;grid-template-columns:minmax(0,1fr)}.dhcp-import>section{min-width:0}.dhcp-import .table-wrap{max-width:100%;min-width:0;overflow-x:auto}.dhcp-form{grid-template-columns:minmax(0,1fr)}.dhcp-import h3,.dhcp-import p{margin:0 0 .5rem}.dhcp-form label{display:grid;gap:.5rem;min-width:0}.dhcp-form input,.dhcp-form textarea{max-width:100%;box-sizing:border-box}.dhcp-results{max-height:28rem;overflow:auto}.dhcp-import td{max-width:28rem;overflow-wrap:anywhere}.dhcp-import td small{display:block}.dhcp-import .inline-actions{flex-wrap:wrap;margin-top:.75rem}
</style>
