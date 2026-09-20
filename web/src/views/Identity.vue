<script setup>
import {onMounted,ref,computed} from 'vue'
import PageHeader from '../components/PageHeader.vue'
import GlassWindow from '../components/GlassWindow.vue'
import {api,session} from '../lib/api.js'
import {useRoute} from 'vue-router'

const route=useRoute()

const segments=ref([]),accessSegments=ref([]),grants=ref([]),nodes=ref([]),groups=ref([]),policies=ref([]),rights=ref([]),challenges=ref([])
const portalBrand=ref({companyName:'WinFire Secure',imageUrl:null})
const error=ref(''),message=ref(''),formOpen=ref(false),manageOpen=ref(false),targetKind=ref('node')
const form=ref({name:'',nodeId:'',nodeGroupId:'',policyId:null,port:3389,accountSid:'',sourceIp:'',ttlMinutes:240,failOpen:false,mode:'agentless',mfaProvider:'totp',portalEnabled:true,autoPromptEnabled:false})
const allowedEmails=ref(''),manageSegment=ref(null),manageEmails=ref(''),manageProvider=ref('totp'),manageEnabled=ref(true),manageTtl=ref(240),manageSource=ref(''),managePolicyId=ref(null),manageAutoPrompt=ref(false)
const accessSegmentId=ref(''),accessNodeId=ref(''),accessCode=ref(''),accessPromptId=ref(''),accessBusy=ref(false),accessResult=ref(null)
const canManage=computed(()=>['owner','admin'].includes(session.user?.role))
const selectedAccess=computed(()=>accessSegments.value.find(item=>item.id===accessSegmentId.value))
const parseEmails=value=>value.split(/[\s,;]+/).map(item=>item.trim().toLowerCase()).filter(Boolean)

async function load(){
  try{
    const [allSegments,eligible,activeGrants,allNodes,allGroups,allPolicies,allRights,branding]=await Promise.all([api('/segments'),api('/segments/access'),api('/segments/access/grants'),api('/nodes'),api('/node-groups'),api('/policies'),api('/logon-rights'),api('/portal-branding')])
    segments.value=allSegments;accessSegments.value=eligible;grants.value=activeGrants;nodes.value=allNodes;groups.value=allGroups;policies.value=allPolicies;rights.value=allRights;portalBrand.value=branding
    const results=await Promise.all(segments.value.map(item=>api(`/segments/${item.id}/challenges`)))
    challenges.value=results.flat();error.value=''
  }catch(cause){error.value=cause.message}
}
async function create(){
  try{
    const payload={...form.value,allowedUpns:parseEmails(allowedEmails.value)}
    if(targetKind.value==='node')delete payload.nodeGroupId;else delete payload.nodeId
    await api('/segments',{method:'POST',body:payload});formOpen.value=false;message.value='Segment created. Only listed operators can request portal access.';await load()
  }catch(cause){error.value=cause.message}
}
function openManage(segment){
  manageSegment.value=segment;manageEmails.value=(JSON.parse(segment.allowed_upns||'[]')).join(', ')
  manageProvider.value=segment.mfa_provider||'totp';manageEnabled.value=!!segment.portal_enabled;manageTtl.value=segment.ttl_minutes;manageSource.value=segment.source_ip||'';managePolicyId.value=segment.policy_id||null;manageAutoPrompt.value=!!segment.auto_prompt_enabled;manageOpen.value=true
}
async function saveManage(){
  try{await api(`/segments/${manageSegment.value.id}`,{method:'PATCH',body:{allowedUpns:parseEmails(manageEmails.value),mfaProvider:manageProvider.value,portalEnabled:manageEnabled.value,ttlMinutes:Number(manageTtl.value),sourceIp:manageSource.value,policyId:managePolicyId.value||null,autoPromptEnabled:manageAutoPrompt.value}});manageOpen.value=false;message.value='Portal settings saved. Existing grants expire on their original schedule.';await load()}
  catch(cause){error.value=cause.message}
}
async function requestAccess(){
  if(!selectedAccess.value)return
  accessBusy.value=true;error.value='';accessResult.value=null
  try{
    if(selectedAccess.value.mfaProvider==='entra'){
      const started=await api(`/segments/${accessSegmentId.value}/entra/start`,{method:'POST',body:{nodeId:accessNodeId.value||undefined,promptId:accessPromptId.value||undefined}})
      window.location.assign(started.authorizationUrl);return
    }
    accessResult.value=await api(`/segments/${accessSegmentId.value}/access`,{method:'POST',body:{nodeId:accessNodeId.value||undefined,promptId:accessPromptId.value||undefined,code:accessCode.value}});accessCode.value='';accessPromptId.value='';await load()
  }
  catch(cause){error.value=cause.message}
  finally{accessBusy.value=false}
}
async function revokeGrant(grant){try{await api(`/segments/access/grants/${grant.id}/revoke`,{method:'POST',body:{}});message.value='Temporary access closed';accessResult.value=null;await load()}catch(cause){error.value=cause.message}}
async function baseline(nodeId){try{await api('/logon-rights/baseline',{method:'POST',body:{nodeId}});await load()}catch(cause){error.value=cause.message}}
onMounted(async()=>{
  await load()
  const promptId=String(route.query.prompt||'')
  if(/^[0-9a-f-]{36}$/i.test(promptId)){
    try{
      const prompt=await api(`/segments/access/prompts/${promptId}`)
      accessSegmentId.value=prompt.segmentId;accessNodeId.value=prompt.nodeId;accessPromptId.value=prompt.id
      message.value=`MFA requested for TCP ${prompt.port} from ${prompt.sourceNode||prompt.sourceIp}${prompt.sessionUser?` (${prompt.sessionUser}, session ${prompt.sessionId})`:''}. Complete the challenge to open temporary access.`
    }catch(cause){error.value=cause.message}
    window.history.replaceState({},'',window.location.pathname)
  }
  const code=String(route.query.code||''),state=String(route.query.state||''),entraError=String(route.query.error_description||route.query.error||'')
  if(code||state||entraError)window.history.replaceState({},'',window.location.pathname)
  if(entraError){error.value=`Entra sign-in failed: ${entraError.slice(0,300)}`;return}
  if(code&&state){accessBusy.value=true;try{accessResult.value=await api('/segments/entra/complete',{method:'POST',body:{code,state}});message.value='Entra MFA complete. Retry your connection now.';await load()}catch(cause){error.value=cause.message}finally{accessBusy.value=false}}
})
</script>

<template>
  <div class="view">
    <PageHeader eyebrow="IDENTITY / SEGMENTATION" title="Identity protection" description="Review access gates and request time-limited RDP or SSH access"><button v-if="canManage" class="button primary" @click="formOpen=true"><i class="mdi mdi-plus"></i> New segment</button></PageHeader>
    <div v-if="error" class="error-msg" role="alert">{{error}}</div><div v-if="message" class="success-msg">{{message}}</div>
    <section class="panel glass portal-panel">
      <div class="panel-title"><div class="portal-brand-header"><img v-if="portalBrand.imageUrl" :src="portalBrand.imageUrl" alt="" class="portal-brand-image"><div><strong class="portal-company-name">{{portalBrand.companyName}}</strong><h2>Request access</h2></div></div><span class="status">Fresh MFA</span></div>
      <p>Choose a protected node and complete its authenticator or Entra challenge. If its firewall gate is ready, WinFire opens TCP access for your current source IP until the grant expires. Then retry your RDP or SSH connection.</p>
      <form class="form-grid portal-form" @submit.prevent="requestAccess">
        <label>Access segment<select v-model="accessSegmentId" required @change="accessNodeId='';accessPromptId='';accessResult=null"><option value="">Choose a segment</option><option v-for="item in accessSegments" :key="item.id" :value="item.id">{{item.name}} · TCP {{item.port}}</option></select></label>
        <label v-if="selectedAccess?.nodes?.length>1">Node<select v-model="accessNodeId" required @change="accessPromptId=''"><option value="">Choose a node</option><option v-for="node in selectedAccess.nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select></label>
        <label v-if="selectedAccess?.mfaProvider!=='entra'">Authenticator code<input v-model.trim="accessCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="000000" required></label>
        <div class="form-actions"><button class="button primary" :disabled="accessBusy||!selectedAccess">{{accessBusy?'Checking…':selectedAccess?.mfaProvider==='entra'?'Continue with Entra':'Open access'}}</button></div>
      </form>
      <p v-if="!accessSegments.length" class="muted">No portal segments are assigned to your account. An administrator can add your email to an agentless segment.</p>
      <p v-if="accessResult" class="success-msg">Access opened for {{accessResult.sourceIp}} to TCP {{accessResult.port}} until {{new Date(accessResult.expiresAt).toLocaleString()}}. Retry your connection now.</p>
      <div v-if="grants.length" class="active-grants"><h3>Active grants</h3><div v-for="grant in grants" :key="grant.id" class="segment-row"><div><strong>{{grant.hostname||grant.node_id}} · TCP {{grant.dst_port}}</strong><small>{{grant.src_ip}} · expires {{new Date(grant.expires_at).toLocaleString()}} · {{grant.fallback_reason?'Fail open: MFA bypassed':grant.user_upn}}</small></div><button class="button small secondary" @click="revokeGrant(grant)">Close access</button></div></div>
      <p class="muted">For authenticator segments, enroll a TOTP app in Administration → Security. Entra segments require a configured tenant app and an MFA Conditional Access policy.</p>
    </section>
    <div class="dashboard-grid">
      <section class="panel glass"><div class="panel-title"><div><span class="eyebrow">POLICY GATES</span><h2>Segments</h2></div><span class="count-chip">{{segments.length}}</span></div>
        <div v-for="segment in segments" :key="segment.id" class="segment-row"><div class="segment-icon"><i class="mdi mdi-shield-lock-outline"></i></div><div><strong>{{segment.name}}</strong><small>{{segment.node_group_id?groups.find(group=>group.id===segment.node_group_id)?.name||segment.node_group_id:nodes.find(node=>node.id===segment.node_id)?.hostname||segment.node_id}} · TCP {{segment.port}} · {{segment.ttl_minutes}} min · {{segment.mfa_provider==='totp'?'Authenticator':'Entra'}} · {{segment.portal_enabled?'Portal on':'Portal off'}} · {{segment.auto_prompt_enabled?'Browser prompt on':'Browser prompt off'}}</small></div><button v-if="canManage" class="button small secondary" @click="openManage(segment)">Manage</button></div>
        <div v-if="!segments.length" class="empty-side">No identity segments configured.</div>
      </section>
      <section class="panel glass"><div class="panel-title"><div><span class="eyebrow">MFA TRAIL</span><h2>Challenges</h2></div><span class="count-chip">{{challenges.length}}</span></div>
        <div v-for="challenge in challenges.slice(0,10)" :key="challenge.id" class="segment-row"><div class="segment-icon"><i class="mdi mdi-account-key-outline"></i></div><div><strong>{{challenge.user_upn}}</strong><small>{{new Date(challenge.challenged_at).toLocaleString()}}</small></div><span class="status" :class="challenge.status">{{challenge.status}}</span></div><div v-if="!challenges.length" class="empty-side">No MFA challenges recorded.</div>
      </section>
    </div>
    <section class="panel glass"><div class="panel-title"><div><span class="eyebrow">WINDOWS LSA</span><h2>Logon rights baseline</h2></div><select v-if="canManage" @change="baseline($event.target.value);$event.target.value=''" aria-label="Collect node baseline"><option value="">Collect from node…</option><option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select></div><div class="table-wrap"><table><thead><tr><th>NODE</th><th>ACCOUNT SID</th><th>LOGON TYPE</th><th>ASSIGNMENT</th><th>RECORDED</th></tr></thead><tbody><tr v-for="right in rights.slice(0,100)" :key="right.id"><td>{{nodes.find(node=>node.id===right.node_id)?.hostname||right.node_id}}</td><td class="mono">{{right.account_sid}}</td><td class="mono">{{right.logon_type}}</td><td>{{right.right_assignment}}</td><td>{{new Date(right.at).toLocaleString()}}</td></tr><tr v-if="!rights.length"><td colspan="5" class="empty-table">No baselines collected yet.</td></tr></tbody></table></div></section>
    <GlassWindow v-model="formOpen" title="New identity segment"><form class="form-grid" @submit.prevent="create"><label>Name<input v-model="form.name" required placeholder="RDP to sensitive servers"></label><label>Target type<select v-model="targetKind"><option value="node">Node</option><option value="group">Node group</option></select></label><label v-if="targetKind==='node'">Target node<select v-model="form.nodeId" required><option value="">Select node</option><option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select></label><label v-else>Target group<select v-model="form.nodeGroupId" required><option value="">Select group</option><option v-for="group in groups" :key="group.id" :value="group.id">{{group.name}}</option></select></label><label>Linked firewall policy<select v-model="form.policyId"><option :value="null">No linked policy</option><option v-for="policy in policies" :key="policy.id" :value="policy.id">{{policy.name}}</option></select></label><label>Target TCP port<input v-model.number="form.port" type="number" min="1" max="65535" required></label><label>Allowed operator emails<input v-model="allowedEmails" placeholder="alice@example.com, bob@example.com" required></label><label>MFA provider<select v-model="form.mfaProvider"><option value="totp">Google Authenticator / TOTP</option><option value="entra">Entra ID (integration required)</option></select></label><label>Source IP/CIDR restriction<input v-model="form.sourceIp" placeholder="10.0.0.0/8"></label><label>Grant TTL (minutes)<input v-model.number="form.ttlMinutes" type="number" min="2" max="10080" required></label><label>Mode<select v-model="form.mode"><option value="agentless">Agentless</option><option value="agent">Agent</option></select></label><label class="check-label"><input v-model="form.portalEnabled" type="checkbox"> Enable portal access</label><label class="check-label"><input v-model="form.autoPromptEnabled" type="checkbox"> Open MFA portal automatically on a matched source workstation</label><p class="muted">Portal grants are firewall only. The target must use WinRM, have enabled firewall profiles with inbound default Block, and have no other allow rule for this port. Automatic prompts require HTTPS, target failure and source success WFP auditing, and a source process in one active user session. AD discovered clients use the directory WinRM credential by default.</p><div class="form-actions"><button class="button primary">Create segment</button></div></form></GlassWindow>
    <GlassWindow v-model="manageOpen" :title="`Manage ${manageSegment?.name||'segment'}`"><form class="form-grid" @submit.prevent="saveManage"><label>Allowed operator emails<input v-model="manageEmails" placeholder="alice@example.com"></label><label>MFA provider<select v-model="manageProvider"><option value="totp">Google Authenticator / TOTP</option><option value="entra">Entra ID (integration required)</option></select></label><label>Linked firewall policy<select v-model="managePolicyId"><option :value="null">No linked policy</option><option v-for="policy in policies" :key="policy.id" :value="policy.id">{{policy.name}}</option></select></label><label>Source IP/CIDR restriction<input v-model="manageSource" placeholder="Any source"></label><label>Grant TTL (minutes)<input v-model.number="manageTtl" type="number" min="2" max="10080" required></label><label class="check-label"><input v-model="manageEnabled" type="checkbox"> Enable portal access</label><label class="check-label"><input v-model="manageAutoPrompt" type="checkbox"> Open browser automatically after a matched blocked connection</label><p class="muted">Disabling the portal stops new grants. Existing grants remain until their scheduled expiry. Automatic prompts use a short event poll and skip ambiguous user sessions.</p><div class="form-actions"><button class="button primary">Save access policy</button></div></form></GlassWindow>
  </div>
</template>

<style scoped>
.portal-panel{margin-bottom:1rem}.portal-panel p{max-width:900px}.portal-form{grid-template-columns:repeat(auto-fit,minmax(200px,1fr));align-items:end}.portal-form .form-actions{margin:0}.segment-row>div:nth-child(2){flex:1;min-width:0}
.portal-brand-header{display:flex;align-items:center;gap:12px;min-width:0}.portal-brand-image{width:58px;height:50px;object-fit:contain;flex:none}
.portal-company-name{display:block;font-size:.75rem;letter-spacing:.03em;color:var(--muted);margin-bottom:3px}
</style>
