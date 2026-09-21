<script setup>
import {computed} from 'vue'

const props=defineProps({node:{type:Object,required:true},rulePage:{type:Object,default:null},rulesLoading:{type:Boolean,default:false},rulesError:{type:String,default:''}})
const emit=defineEmits(['rulesPage'])
const facts=computed(()=>props.node.facts||{})
const identity=computed(()=>facts.value.identity||{})
const adapters=computed(()=>Array.isArray(facts.value.network)?facts.value.network:[])
const profiles=computed(()=>Array.isArray(facts.value.firewall)?facts.value.firewall:facts.value.firewall?[facts.value.firewall]:[])
const value=(item)=>Array.isArray(item)?item.filter(Boolean).join(', ')||'—':item===true?'Yes':item===false?'No':item||'—'
const time=item=>item&&!Number.isNaN(new Date(item).getTime())?new Date(item).toLocaleString():'—'
</script>

<template>
  <div class="node-facts">
    <div v-if="!node.facts" class="info-banner"><i class="mdi mdi-information-outline"></i><span>Host details have not been collected yet. WinRM nodes with a credential are collected automatically after onboarding.</span></div>
      <section class="node-facts-section">
        <h3>Identity and domain</h3>
        <div class="node-facts-grid">
          <div><span>Domain joined</span><strong>{{value(identity.domainJoined ?? facts.computer?.PartOfDomain)}}</strong></div>
          <div><span>Domain name</span><strong>{{value(identity.domainName || facts.computer?.Domain)}}</strong></div>
          <div><span>Inventory source</span><strong>{{value(node.inventory_source)}}</strong></div>
          <div><span>AD account</span><strong>{{node.ad_guid?(node.ad_missing?'Missing from latest sync':node.ad_enabled?'Enabled':'Disabled'):'Not linked'}}</strong></div>
          <div><span>DNS suffixes</span><strong>{{value(facts.dnsSuffixes)}}</strong></div>
          <div><span>Machine GUID</span><strong class="mono">{{value(identity.machineGuid)}}</strong></div>
          <div><span>Local machine SID</span><strong class="mono">{{value(identity.localMachineSid)}}</strong></div>
          <div><span>AD object GUID</span><strong class="mono">{{value(node.ad_guid)}}</strong></div>
          <div><span>AD object SID</span><strong class="mono">{{value(node.ad_sid)}}</strong></div>
          <div><span>AD distinguished name</span><strong class="mono">{{value(node.ad_dn)}}</strong></div>
          <div><span>AD last logon (replicated)</span><strong>{{time(node.ad?.lastLogonAt)}}</strong></div>
          <div><span>Session logon server</span><strong>{{value(identity.sessionLogonServer)}}</strong></div>
          <div><span>Current interactive user</span><strong>{{value(identity.currentInteractiveUser)}}</strong></div>
          <div><span>Last logged-on user</span><strong>{{value(identity.lastLoggedOnUser)}}</strong></div>
        </div>
      </section>
      <section class="node-facts-section">
        <h3>Operating system and hardware</h3>
        <div class="node-facts-grid">
          <div><span>OS</span><strong>{{value(facts.os?.Caption || node.ad?.operatingSystem || node.os_version)}}</strong></div>
          <div><span>Version / build</span><strong>{{value(facts.os?.Version || node.ad?.operatingSystemVersion)}} / {{value(facts.os?.BuildNumber || node.os_build)}}</strong></div>
          <div><span>Architecture</span><strong>{{value(facts.os?.OSArchitecture)}}</strong></div>
          <div><span>Manufacturer / model</span><strong>{{value(facts.computer?.Manufacturer)}} / {{value(facts.computer?.Model)}}</strong></div>
          <div><span>BIOS serial</span><strong class="mono">{{value(facts.bios?.SerialNumber)}}</strong></div>
          <div><span>Installed</span><strong>{{time(facts.os?.InstallDate)}}</strong></div>
          <div><span>Last boot</span><strong>{{time(facts.os?.LastBootUpTime)}}</strong></div>
        </div>
      </section>
    <template v-if="node.facts">
      <section class="node-facts-section">
        <h3>Network interfaces</h3>
        <div v-for="(adapter,index) in adapters" :key="`${adapter.description}-${index}`" class="node-adapter">
          <strong>{{value(adapter.description)}}</strong>
          <div class="node-facts-grid">
            <div><span>IP addresses</span><strong class="mono">{{value(adapter.ipAddresses)}}</strong></div>
            <div><span>Subnets</span><strong class="mono">{{value(adapter.subnets)}}</strong></div>
            <div><span>Gateways</span><strong class="mono">{{value(adapter.gateways)}}</strong></div>
            <div><span>DNS servers</span><strong class="mono">{{value(adapter.dnsServers)}}</strong></div>
            <div><span>DNS domain</span><strong>{{value(adapter.dnsDomain)}}</strong></div>
            <div><span>MAC / DHCP</span><strong class="mono">{{value(adapter.macAddress)}} / {{value(adapter.dhcpEnabled)}}</strong></div>
          </div>
        </div>
        <p v-if="!adapters.length" class="muted">No enabled IP adapters were reported.</p>
      </section>
      <section class="node-facts-section">
        <h3>Firewall profiles</h3>
        <div class="node-profile-grid">
          <div v-for="profile in profiles" :key="profile.Name" class="node-profile">
            <strong>{{profile.Name}}</strong><span :class="['status',profile.Enabled?'reachable':'unknown']">{{profile.Enabled?'Enabled':'Disabled'}}</span>
            <small>Inbound {{value(profile.DefaultInboundAction)}} · Outbound {{value(profile.DefaultOutboundAction)}}</small>
          </div>
        </div>
        <p v-if="!profiles.length" class="muted">Firewall profiles were not reported.</p>
      </section>
    </template>
    <section class="node-facts-section">
      <div class="node-facts-heading"><h3>Current firewall rules</h3><button class="button small secondary" :disabled="rulesLoading||!['winrm','winrms','netsh'].includes(node.transport)" @click="emit('rulesPage',0)"><i class="mdi mdi-refresh"></i> Refresh</button></div>
      <p v-if="!['winrm','winrms','netsh'].includes(node.transport)" class="muted">Live firewall rule inventory is available after a supported management transport connects.</p>
      <p v-else-if="rulesError" class="error-msg">{{rulesError}}</p>
      <p v-else-if="rulesLoading" class="muted">Loading firewall rules…</p>
      <template v-if="rulePage?.rules?.length">
        <div class="table-wrap"><table><thead><tr><th>RULE</th><th>ENABLED</th><th>DIRECTION</th><th>ACTION</th><th>PROTOCOL</th><th>LOCAL</th><th>REMOTE</th><th>SOURCE</th></tr></thead><tbody><tr v-for="rule in rulePage.rules" :key="rule.name"><td :title="rule.name">{{rule.displayName||rule.name}}</td><td>{{rule.enabled?'Yes':'No'}}</td><td>{{rule.direction}}</td><td>{{rule.action}}</td><td>{{rule.protocol}}</td><td>{{rule.localPort}}</td><td :title="rule.remoteAddress">{{rule.remotePort}} · {{rule.remoteAddress}}</td><td>{{rule.source}}</td></tr></tbody></table></div>
        <div class="node-rule-pages"><span>{{rulePage.offset+1}}–{{Math.min(rulePage.offset+rulePage.rules.length,rulePage.total)}} of {{rulePage.total}}</span><div><button class="button small secondary" :disabled="rulesLoading||rulePage.offset===0" @click="emit('rulesPage',Math.max(0,rulePage.offset-100))">Previous</button><button class="button small secondary" :disabled="rulesLoading||rulePage.offset+rulePage.rules.length>=rulePage.total" @click="emit('rulesPage',rulePage.offset+100)">Next</button></div></div>
      </template>
      <p v-else-if="rulePage&&!rulesLoading&&!rulesError" class="muted">No firewall rules were returned.</p>
    </section>
  </div>
</template>
