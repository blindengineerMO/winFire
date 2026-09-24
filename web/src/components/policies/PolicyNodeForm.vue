<script setup>
import {computed} from 'vue'
import {nodeIssue,ruleTypes} from './model.js'
const props=defineProps({node:{type:Object,required:true},readonly:Boolean})
const editor=computed(()=>props.node)
const issue=computed(()=>nodeIssue(editor.value))
defineExpose({issue})
</script>
<template><fieldset class="node-fields form-grid" :disabled="readonly">
<label v-if="ruleTypes.includes(editor.type)">Rule action<select v-model="editor.type" aria-label="Rule action" @change="editor.type!=='deny'&&(editor.data.localUserSid='')"><option value="allow">Allow</option><option value="deny">Reject</option><option value="program">Program allow</option></select></label>
<label>Name<input v-model.trim="editor.data.name" required>
</label>
<template v-if="['allow','deny','program'].includes(editor.type)">
<label>Direction<select v-model="editor.data.direction" aria-label="Direction">
<option value="in">Inbound</option>
<option value="out">Outbound</option>
</select>
</label>
<label>Protocol<select v-model="editor.data.protocol" aria-label="Protocol">
<option>TCP</option>
<option>UDP</option>
<option>Any</option>
</select>
</label>
<label>Local port<input v-model="editor.data.localPort" placeholder="3389 or Any">
</label>
<label>Remote port<input v-model="editor.data.remotePort" placeholder="443 or Any">
</label>
<label>Remote address<input v-model="editor.data.remoteAddress" placeholder="Any or CIDR">
</label>
<label>Program path<input v-model="editor.data.program" placeholder="C:\Program Files\app.exe">
</label>
<label v-if="editor.type==='deny'">Local account SID<input v-model.trim="editor.data.localUserSid" placeholder="All accounts">
</label>
<label>Profile<select v-model="editor.data.profile" aria-label="Profile">
<option>Any</option>
<option>Domain</option>
<option>Private</option>
<option>Public</option>
</select>
</label>
</template>
<label v-if="editor.type==='portGroup'">Ports<input v-model="editor.data.ports" placeholder="80,443">
</label>
<label v-if="editor.type==='addressGroup'">Addresses<input v-model="editor.data.addresses" placeholder="10.0.0.0/8">
</label>
<label v-if="editor.type==='profile'">Profile<select v-model="editor.data.profile" aria-label="Profile">
<option>Any</option>
<option>Domain</option>
<option>Private</option>
<option>Public</option>
</select>
</label>
<template v-if="editor.type==='schedule'">
<label>Days (0 Sunday – 6 Saturday)<input v-model="editor.data.days" placeholder="1,2,3,4,5">
</label>
<label>Start time<input v-model="editor.data.startTime" type="time">
</label>
<label>End time<input v-model="editor.data.endTime" type="time">
</label>
<label>Timezone<input v-model="editor.data.timezone" placeholder="UTC or America/Chicago">
</label>
<p class="hint">Connect this window to an allow/reject rule. Outside the window, the scheduler removes that rule and reapplies it at the next transition.</p>
</template>
<template v-if="editor.type==='mfaGate'">
<label>Target TCP port(s)<input v-model="editor.data.localPort" placeholder="3389">
</label>
<label>Program<input v-model="editor.data.program" placeholder="Any or C:\\Program Files\\App\\app.exe">
</label>
<label>Source asset scope<input v-model="editor.data.sourceAssetScope" placeholder="Any, node ID, or group ID">
</label>
<label>Destination asset scope<input v-model="editor.data.destinationAssetScope" placeholder="Any, node ID, or group ID">
</label>
<label>Source process<input v-model="editor.data.sourceProcess" placeholder="Any or C:\\Program Files\\Client\\client.exe">
</label>
<label>Extra TCP ports<input v-model="editor.data.extraPorts" placeholder="22,5985">
</label>
<label>Entra group ID<input v-model.trim="editor.data.entraGroupId" placeholder="Optional group object ID">
</label>
<label>Session TTL (minutes)<input v-model.number="editor.data.sessionTtlMinutes" type="number" min="1" max="10080">
</label>
<label>Reactive rule TTL (minutes)<input v-model.number="editor.data.reactiveTtlMinutes" type="number" min="1" max="10080">
</label>
<label>Unavailable behavior<select v-model="editor.data.failMode" aria-label="Unavailable behavior">
<option value="closed">Fail closed</option>
<option value="open">Fail open</option>
</select>
</label>
<label class="switch-field">
<span>Fall back to logged-on user</span>
<input v-model="editor.data.fallbackToLoggedOnUser" type="checkbox" role="switch">
<span class="switch-control" aria-hidden="true">
</span>
</label>
<p class="hint">This gate is saved as policy metadata. Deployment remains blocked until the Windows challenge broker is available.</p>
</template>
<p v-if="issue" class="error-msg" role="alert">{{issue}}</p>
</fieldset></template>
<style scoped>
.node-fields{border:0;margin:0;padding:0;min-width:0}.node-fields label{min-width:0}.node-fields input,.node-fields select{width:100%}.node-fields .hint,.node-fields .error-msg{grid-column:1/-1;margin:0}.node-fields:disabled{opacity:1}.node-fields:disabled input,.node-fields:disabled select{color:var(--field-value);opacity:1}@media(max-width:550px){.node-fields{grid-template-columns:1fr}}
</style>
