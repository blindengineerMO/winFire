<script setup>
import {onMounted, ref} from 'vue'
import {api} from '../services/api.js'
import ConfirmDialog from './ConfirmDialog.vue'
import SnmpDiscoverySettings from './SnmpDiscoverySettings.vue'
import DhcpDiscoverySettings from './DhcpDiscoverySettings.vue'
import AzureDiscoverySettings from './AzureDiscoverySettings.vue'
import LinuxDiscoverySettings from './LinuxDiscoverySettings.vue'

const props = defineProps({credentials: {type: Array, default: () => []}})

const activeTab = ref('cidr')
const cidrs = ref(''), scans = ref([]), schedules = ref([]), passive = ref({summary: {}, items: []}), triageWindowDays = ref(7)
const busy = ref(false), scheduleBusy = ref(false), error = ref(''), message = ref(''), passiveAvailable = ref(true)
const preflightBusy = ref(false), preflightResult = ref(null), preflightHost = ref(''), preflightCredentialId = ref('')
const confirmOpen = ref(false), scheduleToDelete = ref(null)
const scheduleForm = ref({name: '', cidrs: '', intervalMinutes: 60, enabled: true})

async function load() {
  error.value = ''
  const [scanResult, scheduleResult, passiveResult, triageResult] = await Promise.allSettled([
    api('/discovery/scans'), api('/discovery/schedules'), api('/discovery/passive-candidates'), api('/settings/discovery-triage')
  ])
  if (scanResult.status === 'fulfilled') scans.value = scanResult.value
  else error.value = scanResult.reason?.message || 'Unable to load discovery scans'
  if (scheduleResult.status === 'fulfilled') schedules.value = scheduleResult.value
  else if (!error.value) error.value = scheduleResult.reason?.message || 'Unable to load discovery schedules'
  if (passiveResult.status === 'fulfilled') { passive.value = passiveResult.value; passiveAvailable.value = true }
  else if (passiveResult.reason?.message === 'Not Found') passiveAvailable.value = false
  else if (!error.value) error.value = passiveResult.reason?.message || 'Unable to load passive discovery candidates'
  if (triageResult.status === 'fulfilled') triageWindowDays.value = Number(triageResult.value.unmanagedAssetWindowDays || 7)
  else if (!error.value) error.value = triageResult.reason?.message || 'Unable to load triage settings'
}
const cidrValues = value => String(value || '').split(/[\n,]/).map(item => item.trim()).filter(Boolean)
const preflightLabel = result => { if (!result) return ''; if (!result.success) return result.onboardingError?.title || result.error || 'Credential test failed'; return `Verified ${(result.transport || 'management').toUpperCase()}${result.computerName ? ` · ${result.computerName}` : ''}` }
const hintConfidence = candidate => { try { return JSON.parse(candidate?.device_type_hint_json || '{}').confidence || 'advisory' } catch { return 'advisory' } }
const diffText = scan => { const summary = scan?.diff?.summary; if (!summary) return '—'; return `${summary.new ?? summary.newCount ?? 0} new · ${summary.gone ?? summary.goneCount ?? 0} dark · ${summary.changed ?? summary.changedCount ?? 0} changed` }
async function scan() { busy.value = true; error.value = ''; message.value = ''; try { const result = await api('/discovery/scans', {method: 'POST', body: {cidrs: cidrValues(cidrs.value)}}); message.value = `Scan queued for ${result.addresses} address${result.addresses === 1 ? '' : 'es'}.`; cidrs.value = ''; await load() } catch (cause) { error.value = cause.message } finally { busy.value = false } }
async function preflightDiscoveryCredential() {
  if (!preflightHost.value.trim() || !preflightCredentialId.value) { preflightResult.value = {success: false, error: 'Enter a host from the CIDR and select a Windows credential.'}; return }
  preflightBusy.value = true; preflightResult.value = null
  try { preflightResult.value = await api(`/credentials/${preflightCredentialId.value}/preflight`, {method: 'POST', body: {host: preflightHost.value.trim()}}) }
  catch (cause) { preflightResult.value = {success: false, error: cause.message} }
  finally { preflightBusy.value = false }
}
async function saveSchedule() { scheduleBusy.value = true; error.value = ''; message.value = ''; try { const form = scheduleForm.value; const result = await api('/discovery/schedules', {method: 'POST', body: {name: form.name, cidrs: cidrValues(form.cidrs), intervalMinutes: Number(form.intervalMinutes), enabled: !!form.enabled}}); message.value = `Schedule “${result.name}” saved.`; scheduleForm.value = {name: '', cidrs: '', intervalMinutes: 60, enabled: true}; await load() } catch (cause) { error.value = cause.message } finally { scheduleBusy.value = false } }
async function toggleSchedule(schedule) { scheduleBusy.value = true; error.value = ''; try { await api(`/discovery/schedules/${schedule.id}`, {method: 'PATCH', body: {enabled: !schedule.enabled}}); await load() } catch (cause) { error.value = cause.message } finally { scheduleBusy.value = false } }
async function runSchedule(schedule) { scheduleBusy.value = true; error.value = ''; message.value = ''; try { const result = await api(`/discovery/schedules/${schedule.id}/run-now`, {method: 'POST', body: {}}); message.value = `Scheduled scan queued (${result.scanId}).`; await load() } catch (cause) { error.value = cause.message } finally { scheduleBusy.value = false } }
function requestDeleteSchedule(schedule) { scheduleToDelete.value = schedule; confirmOpen.value = true }
async function deleteSchedule() { const schedule = scheduleToDelete.value; confirmOpen.value = false; if (!schedule) return; scheduleBusy.value = true; error.value = ''; try { await api(`/discovery/schedules/${schedule.id}`, {method: 'DELETE'}); message.value = 'Discovery schedule removed.'; await load() } catch (cause) { error.value = cause.message } finally { scheduleBusy.value = false; scheduleToDelete.value = null } }
async function processPassive() { busy.value = true; error.value = ''; message.value = ''; try { const result = await api('/discovery/passive-candidates/process', {method: 'POST', body: {}}); message.value = `Processed ${result.processed} passive ARP candidate${result.processed === 1 ? '' : 's'}.`; await load() } catch (cause) { error.value = cause.message } finally { busy.value = false } }
async function saveTriageSettings() { scheduleBusy.value = true; error.value = ''; try { const result = await api('/settings/discovery-triage', {method: 'PATCH', body: {unmanagedAssetWindowDays: Number(triageWindowDays.value)}}); triageWindowDays.value = Number(result.unmanagedAssetWindowDays); message.value = 'Unmanaged asset triage settings saved.' } catch (cause) { error.value = cause.message } finally { scheduleBusy.value = false } }
onMounted(load)
</script>

<template>
  <div class="discovery-settings">
    <div class="panel-title"><div><span class="eyebrow">NETWORK DISCOVERY</span><h2>Discovery sources</h2></div></div>
    <div class="admin-subtabs" role="tablist" aria-label="Discovery source types">
      <button type="button" role="tab" :aria-selected="activeTab === 'cidr'" :class="{active: activeTab === 'cidr'}" @click="activeTab = 'cidr'">CIDR probes</button>
      <button type="button" role="tab" :aria-selected="activeTab === 'snmp'" :class="{active: activeTab === 'snmp'}" @click="activeTab = 'snmp'">SNMP polling</button>
      <button type="button" role="tab" :aria-selected="activeTab === 'arp'" :class="{active: activeTab === 'arp'}" @click="activeTab = 'arp'">ARP / Other</button>
      <button type="button" role="tab" :aria-selected="activeTab === 'linux'" :class="{active: activeTab === 'linux'}" @click="activeTab = 'linux'">Linux</button>
      <button type="button" role="tab" :aria-selected="activeTab === 'dhcp'" :class="{active: activeTab === 'dhcp'}" @click="activeTab = 'dhcp'">DHCP leases</button>
      <button type="button" role="tab" :aria-selected="activeTab === 'azure'" :class="{active: activeTab === 'azure'}" @click="activeTab = 'azure'">Azure / Arc</button>
    </div>
    <AzureDiscoverySettings v-if="activeTab === 'azure'"/>

    <template v-else-if="activeTab === 'cidr'">
      <p class="muted">Probe bounded IPv4 CIDRs with ICMP first, then a same-subnet ARP request and a small TCP management-port fallback (22, 445, 3389, 5985, 5986). Hosts that block ping can still be discovered and are marked with the liveness method used.</p>
      <form class="form-grid" @submit.prevent="scan"><label>CIDRs (one per line)<textarea v-model="cidrs" rows="4" required placeholder="10.20.0.0/24&#10;192.168.50.0/24"></textarea></label><div class="form-actions"><button class="button primary" :disabled="busy">{{busy ? 'Starting…' : 'Start discovery scan'}}</button></div></form><section class="preflight-panel"><div><span class="eyebrow">CREDENTIAL PREFLIGHT</span><h3>Test Windows credentials before discovery</h3><p class="muted">Test a representative host from this subnet before saving it to the discovery workflow. A failed test does not create an asset.</p></div><div class="form-grid preflight-grid"><label>Host or IP<input v-model.trim="preflightHost" placeholder="192.168.50.10"></label><label>Windows credential<select v-model="preflightCredentialId"><option value="">Select credential</option><option v-for="credential in props.credentials.filter(item=>['local','domain'].includes(item.type))" :key="credential.id" :value="credential.id">{{credential.name}} · {{credential.username}}</option></select></label></div><div class="inline-actions"><button type="button" class="button secondary" :disabled="preflightBusy" @click="preflightDiscoveryCredential">{{preflightBusy ? 'Testing…' : 'Test connection'}}</button><span v-if="preflightResult" class="status" :class="preflightResult.success ? 'reachable' : 'failed'">{{preflightLabel(preflightResult)}}</span><small v-if="preflightResult?.onboardingError" class="danger-text">{{preflightResult.onboardingError.remediation}}</small></div></section>
      <section class="triage-settings-panel"><div class="panel-title"><div><span class="eyebrow">COVERAGE WORKFLOW</span><h2>Unmanaged asset triage</h2></div><span class="status pending">{{triageWindowDays}} days</span></div><p class="muted">Hosts discovered in the local CIDRs that require an agent and have no successful WinRM or agent contact for this window appear in the Unmanaged assets tab under Monitored assets.</p><form class="inline-form" @submit.prevent="saveTriageSettings"><label>Wait before triage (days)<input v-model.number="triageWindowDays" type="number" min="1" max="3650" required></label><button class="button small primary" :disabled="scheduleBusy">{{scheduleBusy ? 'Saving…' : 'Save triage window'}}</button></form></section>
      <section class="schedule-panel">
        <div class="panel-title"><div><span class="eyebrow">AUTOMATION</span><h2>Recurring discovery scans</h2></div><span class="status reachable">5 minutes–weekly</span></div>
        <p class="muted">Save a CIDR set to scan repeatedly. Each completed run is compared with the previous run and records new, dark, and changed hosts.</p>
        <form class="form-grid schedule-form" @submit.prevent="saveSchedule"><label>Schedule name<input v-model.trim="scheduleForm.name" required maxlength="120" placeholder="Production LAN"></label><label>CIDRs (one per line)<textarea v-model="scheduleForm.cidrs" rows="3" required placeholder="192.168.50.0/24"></textarea></label><label>Run every (minutes)<input v-model.number="scheduleForm.intervalMinutes" type="number" min="5" max="10080" required><small>5 minutes to 10080 minutes (7 days).</small></label><label class="switch-field"><span>Enable schedule</span><input v-model="scheduleForm.enabled" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><div class="form-actions"><button class="button primary" :disabled="scheduleBusy">{{scheduleBusy ? 'Saving…' : 'Save recurring schedule'}}</button></div></form>
        <div class="table-wrap"><table><thead><tr><th>NAME</th><th>CIDRS</th><th>INTERVAL</th><th>STATUS</th><th>NEXT RUN</th><th>LAST DIFF</th><th>ACTIONS</th></tr></thead><tbody><tr v-for="schedule in schedules" :key="schedule.id"><td>{{schedule.name}}</td><td class="mono">{{schedule.cidrs.join(', ')}}</td><td>{{schedule.intervalMinutes}} min</td><td><span class="status" :class="schedule.enabled ? 'reachable' : 'unknown'">{{schedule.status === 'running' ? 'Running' : schedule.enabled ? 'Enabled' : 'Paused'}}</span><small v-if="schedule.lastError" class="danger-text">{{schedule.lastError}}</small></td><td>{{schedule.next_run_at ? new Date(schedule.next_run_at).toLocaleString() : '—'}}</td><td>{{diffText(scans.find(scan => scan.id === schedule.last_scan_id))}}</td><td><div class="inline-actions"><button class="button small secondary" :disabled="scheduleBusy || schedule.status === 'running'" @click="runSchedule(schedule)">Run now</button><button class="button small secondary" :disabled="scheduleBusy" @click="toggleSchedule(schedule)">{{schedule.enabled ? 'Pause' : 'Enable'}}</button><button class="button small danger" :disabled="scheduleBusy" @click="requestDeleteSchedule(schedule)">Delete</button></div></td></tr><tr v-if="!schedules.length"><td colspan="7" class="empty-table">No recurring discovery schedules yet.</td></tr></tbody></table></div>
      </section>
      <div class="table-wrap"><table><thead><tr><th>CREATED</th><th>CIDRS</th><th>STATUS</th><th>PROBED</th><th>ALIVE</th><th>ARP</th><th>TCP</th><th>REGISTERED</th><th>DIFF</th></tr></thead><tbody><tr v-for="scan in scans" :key="scan.id"><td>{{new Date(scan.created_at).toLocaleString()}}</td><td class="mono">{{scan.cidrs.join(', ')}}</td><td><span class="status" :class="scan.status === 'complete' ? 'reachable' : scan.status === 'failed' ? 'failed' : 'pending'">{{scan.status}}</span></td><td>{{scan.probed}}</td><td>{{scan.alive}}</td><td>{{scan.arp_alive || 0}}</td><td>{{scan.tcp_alive || 0}}</td><td>{{scan.registered}}</td><td>{{scan.schedule_id ? diffText(scan) : '—'}}</td></tr><tr v-if="!scans.length"><td colspan="9" class="empty-table">No discovery scans yet.</td></tr></tbody></table></div>
    </template>

    <SnmpDiscoverySettings v-else-if="activeTab === 'snmp'" :credentials="props.credentials" />

    <LinuxDiscoverySettings v-else-if="activeTab === 'linux'" :credentials="props.credentials" />

    <DhcpDiscoverySettings v-else-if="activeTab === 'dhcp'" />

    <template v-else>
      <section v-if="passiveAvailable" class="passive-discovery"><div class="panel-title"><div><span class="eyebrow">PASSIVE DISCOVERY</span><h2>Managed-node ARP candidates</h2></div><div class="inline-actions"><span class="count-chip">{{passive.summary.queued || 0}} queued</span><button class="button small secondary" :disabled="busy" @click="processPassive">Process now</button></div></div><p class="muted">ARP entries collected from enrolled agents are queued here without interrupting telemetry. Recent internal traffic can add an advisory device-type hint before management verification.</p><div class="table-wrap"><table><thead><tr><th>IP</th><th>MAC</th><th>SOURCE NODE</th><th>PASSIVE HINT</th><th>LAST SEEN</th><th>STATUS</th><th>ERROR</th></tr></thead><tbody><tr v-for="candidate in passive.items" :key="candidate.id"><td class="mono">{{candidate.ip}}</td><td class="mono">{{candidate.mac || '—'}}</td><td>{{candidate.source_hostname}}</td><td><span v-if="candidate.device_type_hint" class="status pending">{{candidate.device_type_hint}}</span><small v-if="candidate.device_type_hint_json" class="muted">{{hintConfidence(candidate)}} confidence</small><span v-if="!candidate.device_type_hint">—</span></td><td>{{new Date(candidate.last_seen_at).toLocaleString()}}</td><td><span class="status" :class="candidate.status === 'registered' ? 'reachable' : candidate.status === 'failed' ? 'unreachable' : 'pending'">{{candidate.status}}</span></td><td class="danger-text">{{candidate.last_error || '—'}}</td></tr><tr v-if="!passive.items.length"><td colspan="7" class="empty-table">No passive ARP candidates are waiting.</td></tr></tbody></table></div></section>
      <section class="other-discovery"><div class="panel-title"><div><span class="eyebrow">OTHER SOURCES</span><h2>ARP and passive discovery</h2></div></div><p class="muted">Use this tab to review ARP candidates gathered from managed nodes and process them through DNS, deduplication, and management verification. Additional passive discovery sources appear here as they are enabled.</p></section>
    </template>

    <div v-if="error" class="error-msg">{{error}}</div><div v-if="message" class="success-msg">{{message}}</div>
    <ConfirmDialog v-model="confirmOpen" title="Delete discovery schedule" :message="`Delete the recurring scan for ${scheduleToDelete?.name || 'this schedule'}? Previous scan history will be retained.`" confirm-label="Delete schedule" @confirm="deleteSchedule" />
  </div>
</template>

<style scoped>
.discovery-settings{display:grid;gap:1rem}.preflight-panel{display:grid;gap:.75rem;border:1px solid var(--border);border-radius:8px;padding:1rem}.preflight-panel h3{margin:.25rem 0}.preflight-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.preflight-panel .muted{padding:0}@media(max-width:700px){.preflight-grid{grid-template-columns:1fr}}.discovery-settings .panel-title{padding:0 0 .8rem}.discovery-settings textarea{width:100%;box-sizing:border-box}.discovery-settings .muted{padding:0 1rem}.triage-settings-panel{display:grid;gap:.75rem;border-top:1px solid var(--border);padding-top:1rem}.triage-settings-panel .panel-title{padding:0 1rem}.triage-settings-panel .inline-form{align-items:end}.triage-settings-panel label{display:grid;gap:.35rem}.schedule-panel{display:grid;gap:.75rem;border-top:1px solid var(--border);padding-top:1rem}.schedule-panel .panel-title{padding:0 1rem}.schedule-form{grid-template-columns:repeat(2,minmax(0,1fr))}.schedule-form label:first-child,.schedule-form label:nth-child(2){grid-column:span 2}.schedule-panel table{min-width:1000px}.schedule-panel td small{display:block}.danger-text{display:block;color:var(--danger)}.passive-discovery,.other-discovery{display:grid;gap:.75rem;border-top:1px solid var(--border);padding-top:1rem}.passive-discovery .panel-title,.other-discovery .panel-title{padding:0 1rem}.other-discovery{min-height:180px}@media(max-width:700px){.schedule-form{grid-template-columns:1fr}.schedule-form label:first-child,.schedule-form label:nth-child(2){grid-column:auto}}
</style>
