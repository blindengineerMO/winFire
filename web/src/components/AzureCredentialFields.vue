<script setup>
const model=defineModel({type:Object,default:()=>({tenantId:'',clientId:'',authMethod:'secret'})})
defineProps({rotating:{type:Boolean,default:false}})
</script>
<template>
  <label>Authentication<select v-model="model.authMethod"><option value="secret">Client secret</option><option value="certificate">Client certificate</option><option value="managed-identity">Managed identity</option><option value="workload-identity">Workload identity</option></select></label>
  <label>Tenant ID<input v-model.trim="model.tenantId" required></label>
  <label>Client ID<input v-model.trim="model.clientId" :required="model.authMethod!=='managed-identity'"><small v-if="model.authMethod==='managed-identity'">Leave empty for the API host’s system-assigned identity.</small></label>
  <label v-if="model.authMethod==='secret'">{{rotating?'New client secret (leave blank to keep current)':'Client secret'}}<input v-model="model.clientSecret" type="password" autocomplete="new-password" :required="!rotating"></label>
  <template v-if="model.authMethod==='certificate'"><label>Certificate PEM<textarea v-model="model.clientCertificatePem" rows="4" :required="!rotating" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label><label>Private key PEM<textarea v-model="model.clientPrivateKeyPem" rows="4" :required="!rotating" autocomplete="off" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></label></template>
  <p class="azure-note">Use Reader access for the selected Azure subscriptions or resource groups. Managed and workload identities require API-host configuration. Secrets use the same encrypted vault as all other credentials.</p>
</template>
<style scoped>label{display:grid;gap:6px;min-width:0}input,select,textarea{min-width:0;width:100%}small,.azure-note{color:var(--muted)}.azure-note{grid-column:1/-1;margin:0}</style>
