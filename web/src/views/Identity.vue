<script setup>
import {onMounted,ref,computed} from 'vue'
import PageHeader from '../components/PageHeader.vue'
import GlassWindow from '../components/GlassWindow.vue'
import {api,session} from '../services/api.js'
import {useRoute} from 'vue-router'

const route=useRoute()

const segments=ref([]),accessSegments=ref([]),grants=ref([]),nodes=ref([]),groups=ref([]),policies=ref([]),rights=ref([]),challenges=ref([])
const logonObservations=ref([]),logonProposals=ref([]),learningNodeId=ref(''),learningSearch=ref(''),learningPage=ref(1),proposalPage=ref(1),learningTruncated=ref(false),learningBusy=ref(false)
const challengePage=ref(1),challengeTotal=ref(0),challengePages=ref(1),challengeStatus=ref(''),challengeSegmentId=ref(''),challengeNodeId=ref(''),challengeProvider=ref(''),challengeUser=ref(''),challengeBusy=ref(false)
const portalBrand=ref({companyName:'WinFire Secure',imageUrl:null})
const error=ref(''),message=ref(''),formOpen=ref(false),manageOpen=ref(false),requestAccessOpen=ref(false),activeTab=ref('segments'),targetKind=ref('node')
const form=ref({name:'',nodeId:'',nodeGroupId:'',policyId:null,port:3389,accountSid:'',sourceIp:'',extraPorts:[],sourceProcess:'',fallbackToLoggedOnUser:false,ttlMinutes:240,failOpen:false,mode:'agentless',mfaProvider:'totp',portalEnabled:true,autoPromptEnabled:false,entraGroupId:''})
const extraPortsText=ref(''),allowedEmails=ref(''),manageSegment=ref(null),manageEmails=ref(''),manageEntraGroupId=ref(''),manageProvider=ref('totp'),manageEnabled=ref(true),manageTtl=ref(240),manageSource=ref(''),managePolicyId=ref(null),manageAutoPrompt=ref(false),manageAccountSid=ref(''),manageExtraPorts=ref(''),manageSourceProcess=ref(''),manageFallback=ref(false),manageFailOpen=ref(false)
const lsaReason=ref(''),lsaConfirmation=ref(false),lsaBusy=ref(false)
const accessSegmentId=ref(''),accessNodeId=ref(''),accessCode=ref(''),accessPromptId=ref(''),accessBusy=ref(false),accessResult=ref(null)
const rightsOpen=ref(false),rightsBusy=ref(false),entraMembersOpen=ref(false),entraMembers=ref([]),entraMembersSegment=ref(null),entraSyncBusy=ref(false)
const rightsForm=ref({nodeId:'',accountSid:'',right:'SeRemoteInteractiveLogonRight',present:true,reason:'',confirmed:false})
const logonRightOptions=['SeNetworkLogonRight','SeDenyNetworkLogonRight','SeRemoteInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeInteractiveLogonRight','SeDenyInteractiveLogonRight','SeBatchLogonRight','SeDenyBatchLogonRight','SeServiceLogonRight','SeDenyServiceLogonRight']
const canManage=computed(()=>['owner','admin'].includes(session.user?.role))
const unsafeNetworkChange=computed(()=>rightsForm.value.right==='SeNetworkLogonRight'&&!rightsForm.value.present||rightsForm.value.right==='SeDenyNetworkLogonRight'&&rightsForm.value.present)
const selectedAccess=computed(()=>accessSegments.value.find(item=>item.id===accessSegmentId.value))
const filteredObservations=computed(()=>logonObservations.value.filter(item=>!learningSearch.value||`${item.accountName||''} ${item.account_sid} ${item.hostname} ${item.source_ip}`.toLowerCase().includes(learningSearch.value.toLowerCase())))
const learningPages=computed(()=>Math.max(1,Math.ceil(filteredObservations.value.length/20)))
const visibleObservations=computed(()=>filteredObservations.value.slice((learningPage.value-1)*20,learningPage.value*20))
const filteredProposals=computed(()=>logonProposals.value.filter(item=>!learningSearch.value||`${item.accountName||''} ${item.accountSid} ${item.hostname} ${item.sourceIps.join(' ')}`.toLowerCase().includes(learningSearch.value.toLowerCase())))
const proposalPages=computed(()=>Math.max(1,Math.ceil(filteredProposals.value.length/10)))
const visibleProposals=computed(()=>filteredProposals.value.slice((proposalPage.value-1)*10,proposalPage.value*10))
const tabs=computed(()=>[
  {id:'segments',label:'Access segments',count:segments.value.length,icon:'mdi-shield-lock-outline'},
  {id:'challenges',label:'MFA challenges',count:challengeTotal.value,icon:'mdi-account-key-outline'},
  {id:'rights',label:'Logon rights',count:rights.value.length,icon:'mdi-key-chain'},
  {id:'learning',label:'Learning preview',count:logonProposals.value.length+logonObservations.value.length,icon:'mdi-chart-timeline-variant'}
])
const parseEmails=value=>value.split(/[\s,;]+/).map(item=>item.trim().toLowerCase()).filter(Boolean)
function parseExtraPorts(value,primary){
  const tokens=value.split(/[\s,;]+/).map(item=>item.trim()).filter(Boolean)
  if(tokens.some(token=>!/^\d+$/.test(token)||Number(token)<1||Number(token)>65535))throw new Error('Extra ports must be TCP port numbers from 1 to 65535')
  return [...new Set(tokens.map(Number))].filter(port=>port!==Number(primary))
}

async function load(){
  try{
    const [allSegments,eligible,activeGrants,allNodes,allGroups,allPolicies,allRights,branding]=await Promise.all([api('/segments'),api('/segments/access'),api('/segments/access/grants'),api('/nodes'),api('/node-groups'),api('/policies'),api('/logon-rights'),api('/portal-branding')])
    segments.value=allSegments;accessSegments.value=eligible;grants.value=activeGrants;nodes.value=allNodes;groups.value=allGroups;policies.value=allPolicies;rights.value=allRights;portalBrand.value=branding
    error.value='';await Promise.all([loadChallenges(),loadLogonLearning()])
  }catch(cause){error.value=cause.message}
}
async function loadChallenges(){
  challengeBusy.value=true
  try{
    const query=new URLSearchParams({page:String(challengePage.value),pageSize:'10'})
    if(challengeStatus.value)query.set('status',challengeStatus.value)
    if(challengeSegmentId.value)query.set('segmentId',challengeSegmentId.value)
    if(challengeNodeId.value)query.set('nodeId',challengeNodeId.value)
    if(challengeProvider.value)query.set('provider',challengeProvider.value)
    if(challengeUser.value.trim())query.set('userUpn',challengeUser.value.trim())
    const result=await api(`/mfa/challenges/search?${query}`)
    challenges.value=result.items;challengeTotal.value=result.total;challengePages.value=Math.max(1,result.totalPages)
  }catch(cause){error.value=cause.message}
  finally{challengeBusy.value=false}
}
function searchChallenges(){challengePage.value=1;loadChallenges()}
function moveChallengePage(next){if(next<1||next>challengePages.value||challengeBusy.value)return;challengePage.value=next;loadChallenges()}
async function loadLogonLearning(){
  learningBusy.value=true
  try{const query=new URLSearchParams({days:'30'});if(learningNodeId.value)query.set('nodeId',learningNodeId.value);const result=await api(`/identity/learning-preview?${query}`);logonObservations.value=result.items;logonProposals.value=result.proposals||[];learningTruncated.value=result.truncated;learningPage.value=1;proposalPage.value=1}
  catch(cause){error.value=cause.message}
  finally{learningBusy.value=false}
}
function challengeConnection(challenge){
  try{const connection=JSON.parse(challenge.connection_5tuple||'null');return connection?.srcIp&&connection?.dstPort?`${connection.srcIp} → TCP ${connection.dstPort}`:null}
  catch{return null}
}
function openAccessDialog(){error.value='';accessResult.value=null;requestAccessOpen.value=true}
async function create(){
  try{
    const payload={...form.value,extraPorts:parseExtraPorts(extraPortsText.value,form.value.port),allowedUpns:parseEmails(allowedEmails.value)}
    if(!payload.allowedUpns.length&&!payload.entraGroupId.trim())throw new Error('Enter an operator email or an AD/Entra group')
    if(targetKind.value==='node')delete payload.nodeGroupId;else delete payload.nodeId
    await api('/segments',{method:'POST',body:payload});formOpen.value=false;message.value='Segment created. Only listed operators can request portal access.';await load()
  }catch(cause){error.value=cause.message}
}
function openManage(segment){
  manageSegment.value=segment;manageEmails.value=(JSON.parse(segment.allowed_upns||'[]')).join(', ')
  manageEntraGroupId.value=segment.entra_group_id||''
  manageProvider.value=segment.mfa_provider||'totp';manageEnabled.value=!!segment.portal_enabled;manageTtl.value=segment.ttl_minutes;manageSource.value=segment.source_ip||'';managePolicyId.value=segment.policy_id||null;manageAutoPrompt.value=!!segment.auto_prompt_enabled;manageAccountSid.value=segment.account_sid||'';manageExtraPorts.value=(JSON.parse(segment.extra_ports||'[]')).join(', ');manageSourceProcess.value=segment.source_process||'';manageFallback.value=!!segment.fallback_to_logged_on_user;manageFailOpen.value=!!segment.fail_open;manageOpen.value=true
}
async function saveManage(){
  try{const allowedUpns=parseEmails(manageEmails.value);if(!allowedUpns.length&&!manageEntraGroupId.value.trim())throw new Error('Enter an operator email or an AD/Entra group');await api(`/segments/${manageSegment.value.id}`,{method:'PATCH',body:{allowedUpns,entraGroupId:manageEntraGroupId.value,mfaProvider:manageProvider.value,portalEnabled:manageEnabled.value,ttlMinutes:Number(manageTtl.value),sourceIp:manageSource.value,policyId:managePolicyId.value||null,autoPromptEnabled:manageAutoPrompt.value,accountSid:manageAccountSid.value,extraPorts:parseExtraPorts(manageExtraPorts.value,manageSegment.value.port),sourceProcess:manageSourceProcess.value,fallbackToLoggedOnUser:manageFallback.value,failOpen:manageFailOpen.value}});manageOpen.value=false;message.value='Segment settings saved. Existing grants expire on their original schedule.';await load()}
  catch(cause){error.value=cause.message}
}
async function syncEntraMembers(segment){
  entraMembersSegment.value=segment;entraMembersOpen.value=true;entraMembers.value=[];entraSyncBusy.value=true;error.value=''
  try{await api(`/segments/${segment.id}/entra-group/sync`,{method:'POST',body:{}});const result=await api(`/segments/${segment.id}/entra-group/members`);entraMembers.value=result.members;message.value=`Entra group synced: ${result.members.length} member${result.members.length===1?'':'s'}.`}
  catch(cause){error.value=cause.message}
  finally{entraSyncBusy.value=false}
}
async function setLsaBaseline(enabled){
  if(!manageSegment.value)return
  lsaBusy.value=true;error.value=''
  try{
    await api(`/segments/${manageSegment.value.id}/lsa-baselines`,{method:'POST',body:{enabled,reason:lsaReason.value,confirmed:lsaConfirmation.value}})
    await load();manageSegment.value=segments.value.find(item=>item.id===manageSegment.value.id)||manageSegment.value
    lsaReason.value='';lsaConfirmation.value=false;message.value=enabled?'LSA deny baseline enforced and verified on the segment targets.':'Original LSA assignments restored and verified.'
  }catch(cause){error.value=cause.message}
  finally{lsaBusy.value=false}
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
function reviewProposal(proposal){
  rightsForm.value={nodeId:proposal.nodeId,accountSid:proposal.accountSid,right:proposal.suggestedRight,present:true,reason:'',confirmed:false}
  rightsOpen.value=true
}
async function changeLogonRight(){
  rightsBusy.value=true;error.value=''
  try{
    const result=await api('/logon-rights/change',{method:'POST',body:rightsForm.value})
    await api('/logon-rights/baseline',{method:'POST',body:{nodeId:rightsForm.value.nodeId}})
    rightsOpen.value=false;rightsForm.value={nodeId:'',accountSid:'',right:'SeRemoteInteractiveLogonRight',present:true,reason:'',confirmed:false}
    await load();message.value=result.changed?'Logon right changed and verified on the Windows node.':'Logon right was already in the requested state.'
  }catch(cause){error.value=cause.message}
  finally{rightsBusy.value=false}
}
onMounted(async()=>{
  await load()
  const promptId=String(route.query.prompt||'')
  if(/^[0-9a-f-]{36}$/i.test(promptId)){
    try{
      const prompt=await api(`/segments/access/prompts/${promptId}`)
      accessSegmentId.value=prompt.segmentId;accessNodeId.value=prompt.nodeId;accessPromptId.value=prompt.id
      requestAccessOpen.value=true
      message.value=`MFA requested for TCP ${prompt.port} from ${prompt.sourceNode||prompt.sourceIp}${prompt.sessionUser?` (${prompt.sessionUser}, session ${prompt.sessionId})`:''}. Complete the challenge to open temporary access.`
    }catch(cause){error.value=cause.message}
    window.history.replaceState({},'',window.location.pathname)
  }
  const code=String(route.query.code||''),state=String(route.query.state||''),entraError=String(route.query.error_description||route.query.error||'')
  if(code||state||entraError)window.history.replaceState({},'',window.location.pathname)
  if(entraError){
    const errorCode=String(route.query.error||'')
    if(state&&/^[A-Za-z0-9_]{1,64}$/.test(errorCode)){
      try{await api('/segments/entra/cancel',{method:'POST',body:{state,error:errorCode}});await loadChallenges()}
      catch(cause){error.value=cause.message;return}
    }
    error.value=`Entra sign-in failed: ${entraError.slice(0,300)}`;requestAccessOpen.value=true;return
  }
  if(code&&state){requestAccessOpen.value=true;accessBusy.value=true;try{accessResult.value=await api('/segments/entra/complete',{method:'POST',body:{code,state}});message.value='Entra MFA complete. Retry your connection now.';await load()}catch(cause){error.value=cause.message}finally{accessBusy.value=false}}
})
</script>

<template>
  <div class="view">
    <PageHeader eyebrow="IDENTITY / SEGMENTATION" title="Identity protection" description="Review access gates and request time-limited RDP or SSH access">
      <button type="button" class="button secondary" @click="openAccessDialog"><i class="mdi mdi-key-plus"></i> Request access</button>
      <button v-if="canManage" type="button" class="button primary" @click="formOpen=true"><i class="mdi mdi-plus"></i> New segment</button>
    </PageHeader>
    <div v-if="error" class="error-msg" role="alert">{{error}}</div>
    <div v-if="message" class="success-msg" role="status">{{message}}</div>

    <section class="panel glass identity-tabs-shell">
      <nav class="identity-tabs" role="tablist" aria-label="Identity tables">
        <button v-for="tab in tabs" :key="tab.id" type="button" role="tab" :id="`identity-tab-${tab.id}`" :aria-selected="activeTab===tab.id" :aria-controls="`identity-panel-${tab.id}`" :class="{active:activeTab===tab.id}" @click="activeTab=tab.id">
          <i class="mdi" :class="tab.icon" aria-hidden="true"></i><span>{{tab.label}}</span><span class="count-chip">{{tab.count}}</span>
        </button>
      </nav>

      <section v-if="activeTab==='segments'" id="identity-panel-segments" class="identity-tab-panel" role="tabpanel" aria-labelledby="identity-tab-segments" tabindex="0">
        <div class="panel-title"><div><span class="eyebrow">POLICY GATES</span><h2>Access segments</h2><p class="tab-description">Protected nodes and groups that can issue temporary RDP or SSH access after MFA.</p></div><button type="button" class="button small primary" @click="openAccessDialog"><i class="mdi mdi-key-plus"></i> Request access</button></div>
        <div v-for="segment in segments" :key="segment.id" class="segment-row">
          <div class="segment-icon"><i class="mdi mdi-shield-lock-outline"></i></div>
          <div><strong>{{segment.name}}</strong><small>{{segment.node_group_id?groups.find(group=>group.id===segment.node_group_id)?.name||segment.node_group_id:nodes.find(node=>node.id===segment.node_id)?.hostname||segment.node_id}} · TCP {{segment.port}} · {{segment.ttl_minutes}} min · {{segment.mfa_provider==='totp'?'Authenticator':'Entra'}} · {{segment.portal_enabled?'Portal on':'Portal off'}} · {{segment.auto_prompt_enabled?'Browser prompt on':'Browser prompt off'}}</small><small v-if="segment.entra_group_id" class="learning-sid">Directory group: {{segment.entra_group_id}}</small></div>
          <div class="segment-actions"><button v-if="canManage&&segment.entra_group_id" type="button" class="button small secondary" :disabled="entraSyncBusy" @click="syncEntraMembers(segment)">Sync group</button><button v-if="canManage" type="button" class="button small secondary" @click="openManage(segment)">Manage</button></div>
        </div>
        <div v-if="!segments.length" class="empty-side">No identity segments configured.</div>
        <div class="tab-footnote"><span><i class="mdi mdi-information-outline"></i> Access requests are scoped to your account and current source IP.</span><button type="button" class="button small secondary" @click="openAccessDialog">Open request dialog</button></div>
      </section>

      <section v-else-if="activeTab==='challenges'" id="identity-panel-challenges" class="identity-tab-panel" role="tabpanel" aria-labelledby="identity-tab-challenges" tabindex="0">
        <div class="panel-title"><div><span class="eyebrow">MFA TRAIL</span><h2>Authentication challenges</h2><p class="tab-description">Search every pending, approved, denied, and expired identity challenge.</p></div><span class="count-chip">{{challengeTotal}} total</span></div>
        <div class="challenge-filters"><select v-model="challengeSegmentId" aria-label="Filter challenges by segment" @change="searchChallenges"><option value="">All segments</option><option v-for="segment in segments" :key="segment.id" :value="segment.id">{{segment.name}}</option></select><select v-model="challengeNodeId" aria-label="Filter challenges by node" @change="searchChallenges"><option value="">All nodes</option><option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select><select v-model="challengeProvider" aria-label="Filter challenges by provider" @change="searchChallenges"><option value="">All providers</option><option value="totp">Authenticator</option><option value="entra">Entra</option><option value="manual">Manual</option></select><select v-model="challengeStatus" aria-label="Filter challenges by result" @change="searchChallenges"><option value="">All results</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="denied">Denied</option><option value="expired">Expired</option></select><input v-model="challengeUser" aria-label="Search challenge user" placeholder="Search user" @keyup.enter="searchChallenges"><button type="button" class="button small secondary" :disabled="challengeBusy" @click="searchChallenges">Search</button></div>
        <div class="challenge-table-wrap">
          <table><thead><tr><th>USER</th><th>SEGMENT / NODE</th><th>PROVIDER</th><th>CONNECTION</th><th>CHALLENGED</th><th>RESULT</th></tr></thead><tbody>
            <tr v-for="challenge in challenges" :key="challenge.id"><td><strong>{{challenge.user_upn}}</strong></td><td>{{challenge.segment_name||challenge.segment_id}}<small>{{challenge.node_name||challenge.node_id}}</small></td><td>{{challenge.provider||'Unknown provider'}}</td><td class="mono">{{challengeConnection(challenge)||'—'}}</td><td>{{new Date(challenge.challenged_at).toLocaleString()}}<small v-if="challenge.resolved_at">Resolved {{new Date(challenge.resolved_at).toLocaleString()}}</small></td><td><span class="status" :class="challenge.status">{{challenge.status}}</span><small v-if="challenge.failure_reason" class="danger-text">{{challenge.failure_reason}}</small></td></tr>
            <tr v-if="!challenges.length"><td colspan="6" class="empty-table">{{challengeBusy?'Loading challenges…':'No MFA challenges match these filters.'}}</td></tr>
          </tbody></table>
        </div>
        <div v-if="challengeTotal>10" class="challenge-pages"><span>Page {{challengePage}} of {{challengePages}}</span><div><button type="button" class="button small secondary" :disabled="challengePage<=1||challengeBusy" @click="moveChallengePage(challengePage-1)">Previous</button><button type="button" class="button small secondary" :disabled="challengePage>=challengePages||challengeBusy" @click="moveChallengePage(challengePage+1)">Next</button></div></div>
      </section>

      <section v-else-if="activeTab==='rights'" id="identity-panel-rights" class="identity-tab-panel" role="tabpanel" aria-labelledby="identity-tab-rights" tabindex="0">
        <div class="panel-title"><div><span class="eyebrow">WINDOWS LSA</span><h2>Logon rights baseline</h2><p class="tab-description">Assignments captured from managed Windows nodes, resolved to AD or local accounts.</p></div><div v-if="canManage" class="rights-actions"><select @change="baseline($event.target.value);$event.target.value=''" aria-label="Collect node baseline"><option value="">Collect from node…</option><option v-for="node in nodes.filter(item=>['winrm','winrms'].includes(item.transport))" :key="node.id" :value="node.id">{{node.hostname}}</option></select><button type="button" class="button secondary" @click="rightsOpen=true">Change logon right</button></div></div>
        <div class="table-wrap"><table><thead><tr><th>NODE</th><th>ACCOUNT</th><th>SOURCE</th><th>ACCOUNT SID</th><th>LOGON TYPE</th><th>ASSIGNMENT</th><th>RECORDED</th></tr></thead><tbody><tr v-for="right in rights.slice(0,100)" :key="right.id"><td>{{nodes.find(node=>node.id===right.node_id)?.hostname||right.node_id}}</td><td>{{right.accountName||'Unresolved'}}</td><td>{{right.accountSource||'—'}}</td><td class="mono">{{right.account_sid}}</td><td class="mono">{{right.logon_type}}</td><td>{{right.right_assignment}}</td><td>{{new Date(right.at).toLocaleString()}}</td></tr><tr v-if="!rights.length"><td colspan="7" class="empty-table">No baselines collected yet.</td></tr></tbody></table></div>
        <p v-if="rights.length>100" class="tab-footnote"><span>Showing the first 100 records. Collect a node baseline to refresh its current assignments.</span></p>
      </section>

      <section v-else id="identity-panel-learning" class="identity-tab-panel" role="tabpanel" aria-labelledby="identity-tab-learning" tabindex="0">
        <div class="panel-title"><div><span class="eyebrow">LOGON TELEMETRY</span><h2>Identity learning preview</h2><p class="tab-description">Review successful and failed Windows logons before creating an identity gate.</p></div><div class="rights-actions"><select v-model="learningNodeId" aria-label="Filter logon learning by node" @change="loadLogonLearning"><option value="">All nodes</option><option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select><button type="button" class="button small secondary" :disabled="learningBusy" @click="loadLogonLearning">{{learningBusy?'Loading…':'Refresh'}}</button></div></div>
        <p class="learning-intro">Observed Windows 4624/4625 logons from the last 30 days. Service, interactive, and network labels describe the Windows logon type, not the account owner.</p>
        <div class="learning-search"><input v-model.trim="learningSearch" aria-label="Search logon observations" placeholder="Search account, SID, node or source IP" @input="learningPage=1;proposalPage=1"><span v-if="learningTruncated" class="muted">Showing the 500 most recent groups. Select a node to narrow the result.</span></div>
        <div class="learning-section"><h3>Rights to review</h3><p class="learning-intro">Successful logons suggest a Windows right to inspect. Direct assignments may be absent because a group grants access.</p><div class="table-wrap"><table><thead><tr><th>NODE</th><th>ACCOUNT</th><th>OBSERVED LOGON</th><th>RIGHT TO REVIEW</th><th>SUCCESS</th><th>DIRECT ASSIGNMENT</th><th v-if="canManage">ACTION</th></tr></thead><tbody><tr v-for="item in visibleProposals" :key="`${item.nodeId}:${item.accountSid}:${item.suggestedRight}`"><td>{{item.hostname}}</td><td><strong>{{item.accountName||'Unresolved'}}</strong><small class="learning-sid">{{item.accountSid}}</small></td><td>{{item.classification}}<small class="learning-sid">{{item.sourceIps.join(', ')||'Source unknown'}}</small></td><td class="mono">{{item.suggestedRight}}</td><td>{{item.successes}}</td><td>{{item.status==='already-direct'?'Allow assigned':item.status==='explicit-deny'?'Explicit deny':item.status==='collect-baseline'?'Baseline needed':'No direct allow'}}</td><td v-if="canManage"><button v-if="item.status==='collect-baseline'" type="button" class="button small secondary" @click="baseline(item.nodeId)">Collect baseline</button><button v-else-if="item.status==='review'" type="button" class="button small secondary" @click="reviewProposal(item)">Review change</button><span v-else>—</span></td></tr><tr v-if="!visibleProposals.length"><td :colspan="canManage?7:6" class="empty-table">{{learningBusy?'Loading suggestions…':'No successful account logons to review.'}}</td></tr></tbody></table></div><div v-if="proposalPages>1" class="challenge-pages"><span>Suggestions page {{proposalPage}} of {{proposalPages}}</span><div><button type="button" class="button small secondary" :disabled="proposalPage<=1" @click="proposalPage--">Previous</button><button type="button" class="button small secondary" :disabled="proposalPage>=proposalPages" @click="proposalPage++">Next</button></div></div></div>
        <div class="learning-section"><h3>Observed logons</h3><div class="table-wrap"><table><thead><tr><th>NODE</th><th>ACCOUNT</th><th>TYPE</th><th>SOURCE</th><th>SUCCESS</th><th>FAILURE</th><th>LAST SEEN</th></tr></thead><tbody><tr v-for="item in visibleObservations" :key="`${item.node_id}:${item.account_sid}:${item.logon_type}:${item.source_ip}`"><td>{{item.hostname}}</td><td><strong>{{item.accountName||'Unresolved'}}</strong><small class="learning-sid">{{item.account_sid}}</small></td><td>{{item.classification}} · {{item.logon_type||'?'}}</td><td class="mono">{{item.source_ip||'Unknown'}}</td><td>{{item.successes}}</td><td>{{item.failures}}</td><td>{{new Date(item.last_seen_at).toLocaleString()}}</td></tr><tr v-if="!visibleObservations.length"><td colspan="7" class="empty-table">{{learningBusy?'Loading observations…':'No logon observations match this view.'}}</td></tr></tbody></table></div><div v-if="learningPages>1" class="challenge-pages"><span>Observations page {{learningPage}} of {{learningPages}}</span><div><button type="button" class="button small secondary" :disabled="learningPage<=1" @click="learningPage--">Previous</button><button type="button" class="button small secondary" :disabled="learningPage>=learningPages" @click="learningPage++">Next</button></div></div></div>
      </section>
    </section>

    <GlassWindow v-model="requestAccessOpen" title="Request protected access" width="620px">
      <div class="request-access-dialog">
        <div class="request-access-hero"><div class="portal-brand-header"><img v-if="portalBrand.imageUrl" :src="portalBrand.imageUrl" alt="" class="portal-brand-image"><div><strong class="portal-company-name">{{portalBrand.companyName}}</strong><h2>Verify your connection</h2></div></div><span class="status">Fresh MFA</span></div>
        <p class="request-access-copy">Choose a protected resource and complete its authenticator or Entra challenge. WinFire will open TCP access for your current source IP until the grant expires.</p>
        <form class="form-grid portal-form" @submit.prevent="requestAccess">
          <label>Access segment<select v-model="accessSegmentId" required @change="accessNodeId='';accessPromptId='';accessResult=null"><option value="">Choose a segment</option><option v-for="item in accessSegments" :key="item.id" :value="item.id">{{item.name}} · TCP {{item.port}}</option></select></label>
          <label v-if="selectedAccess?.nodes?.length>1">Node<select v-model="accessNodeId" required @change="accessPromptId=''"><option value="">Choose a node</option><option v-for="node in selectedAccess.nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select></label>
          <p v-else-if="selectedAccess?.nodes?.length===1" class="selected-target"><span class="eyebrow">TARGET</span><strong>{{selectedAccess.nodes[0].hostname}}</strong></p>
          <label v-if="selectedAccess&&selectedAccess.mfaProvider!=='entra'">Authenticator code<input v-model.trim="accessCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="000000" required></label>
          <div class="form-actions"><button type="button" class="button secondary" @click="requestAccessOpen=false">Cancel</button><button type="submit" class="button primary" :disabled="accessBusy||!selectedAccess">{{accessBusy?'Checking…':selectedAccess?.mfaProvider==='entra'?'Continue with Entra':'Request access'}}</button></div>
        </form>
        <p v-if="!accessSegments.length" class="muted">No portal segments are assigned to your account. An administrator can add your email to an identity segment.</p>
        <p v-if="accessResult" class="success-msg" role="status">Access opened for {{accessResult.sourceIp}} to TCP {{accessResult.port}} until {{new Date(accessResult.expiresAt).toLocaleString()}}. Retry your connection now.</p>
        <div v-if="grants.length" class="active-grants"><div class="panel-title"><h3>Active grants</h3><span class="count-chip">{{grants.length}}</span></div><div v-for="grant in grants" :key="grant.id" class="segment-row"><div><strong>{{grant.hostname||grant.node_id}} · TCP {{(grant.ports||[grant.dst_port]).join(', ')}}</strong><small>{{grant.src_ip}} · expires {{new Date(grant.expires_at).toLocaleString()}} · {{grant.fallback_reason?'Fail open: MFA bypassed':grant.user_upn}}</small></div><button type="button" class="button small secondary" @click="revokeGrant(grant)">Close access</button></div></div>
        <p class="muted">Authenticator segments require a TOTP enrollment in Administration → Security. Entra segments require a configured tenant app and MFA Conditional Access policy.</p>
      </div>
    </GlassWindow>
    <GlassWindow v-model="formOpen" title="New identity segment"><form class="form-grid" @submit.prevent="create"><label>Name<input v-model="form.name" required placeholder="RDP to sensitive servers"></label><label>Target type<select v-model="targetKind"><option value="node">Node</option><option value="group">Node group</option></select></label><label v-if="targetKind==='node'">Target node<select v-model="form.nodeId" required><option value="">Select node</option><option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option></select></label><label v-else>Target group<select v-model="form.nodeGroupId" required><option value="">Select group</option><option v-for="group in groups" :key="group.id" :value="group.id">{{group.name}}</option></select></label><label>Linked firewall policy<select v-model="form.policyId"><option :value="null">No linked policy</option><option v-for="policy in policies" :key="policy.id" :value="policy.id">{{policy.name}}</option></select></label><label>Target TCP port<input v-model.number="form.port" type="number" min="1" max="65535" required></label><label>Allowed operator emails<input v-model="allowedEmails" placeholder="alice@example.com, bob@example.com"></label><label>AD/Entra group scope<input v-model.trim="form.entraGroupId" placeholder="Optional synced group DN or object ID"></label><label>MFA provider<select v-model="form.mfaProvider"><option value="totp">Google Authenticator / TOTP</option><option value="entra">Entra ID (integration required)</option></select></label><label>Source IP/CIDR restriction<input v-model="form.sourceIp" placeholder="10.0.0.0/8"></label><label>Account SID<input v-model.trim="form.accountSid" placeholder="S-1-5-21-…"></label><label>Extra TCP ports<input v-model.trim="extraPortsText" placeholder="22, 5985"></label><label>Source process<input v-model.trim="form.sourceProcess" placeholder="C:\Program Files\App\app.exe"></label><label class="switch-field"><span>Fall back to logged-on user</span><input v-model="form.fallbackToLoggedOnUser" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><label class="switch-field"><span>Fail open when the gate is unavailable</span><input v-model="form.failOpen" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><label>Grant TTL (minutes)<input v-model.number="form.ttlMinutes" type="number" min="2" max="10080" required></label><label>Mode<select v-model="form.mode"><option value="agentless">Agentless</option><option value="agent">Agent</option></select></label><label class="switch-field"><span>Enable portal access</span><input v-model="form.portalEnabled" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><label class="switch-field"><span>Open MFA portal automatically on a matched source workstation</span><input v-model="form.autoPromptEnabled" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><p class="muted">Operator emails and the synced AD/Entra group are alternative scopes. Directory membership uses the latest AD sync and, for a group object ID, a cached Microsoft Graph lookup; administrators can sync and inspect members from the segment list. Agentless portal grants enforce the primary and extra TCP ports for one source IP. Account SID, source process, and logged-on-user fallback are stored for future gate enforcement; enabling any of them or fail open disables portal grants. The target must use WinRM, have enabled firewall profiles with inbound default Block, and have no overlapping allow rule for any configured port. Automatic prompts require HTTPS, target failure and source success WFP auditing, and a source process in one active user session. AD discovered clients use the directory WinRM credential by default.</p><div class="form-actions"><button class="button primary">Create segment</button></div></form></GlassWindow>
    <GlassWindow v-model="manageOpen" :title="`Manage ${manageSegment?.name||'segment'}`"><form class="form-grid" @submit.prevent="saveManage"><label>Allowed operator emails<input v-model="manageEmails" placeholder="alice@example.com"></label><label>AD/Entra group scope<input v-model.trim="manageEntraGroupId" placeholder="Optional synced group DN or object ID"></label><label>MFA provider<select v-model="manageProvider"><option value="totp">Google Authenticator / TOTP</option><option value="entra">Entra ID (integration required)</option></select></label><label>Linked firewall policy<select v-model="managePolicyId"><option :value="null">No linked policy</option><option v-for="policy in policies" :key="policy.id" :value="policy.id">{{policy.name}}</option></select></label><label>Source IP/CIDR restriction<input v-model="manageSource" placeholder="Any source"></label><label>Account SID<input v-model.trim="manageAccountSid" placeholder="S-1-5-21-…"></label><label>Extra TCP ports<input v-model.trim="manageExtraPorts" placeholder="22, 5985"></label><label>Source process<input v-model.trim="manageSourceProcess" placeholder="C:\Program Files\App\app.exe"></label><label class="switch-field"><span>Fall back to logged-on user</span><input v-model="manageFallback" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><label class="switch-field"><span>Fail open when the gate is unavailable</span><input v-model="manageFailOpen" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><label>Grant TTL (minutes)<input v-model.number="manageTtl" type="number" min="2" max="10080" required></label><label class="switch-field"><span>Enable portal access</span><input v-model="manageEnabled" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><label class="switch-field"><span>Open browser automatically after a matched blocked connection</span><input v-model="manageAutoPrompt" type="checkbox" role="switch"><span class="switch-control" aria-hidden="true"></span></label><p class="muted">Disabling the portal stops new grants. Existing grants remain until their scheduled expiry. Group membership uses the latest AD sync and cached Graph membership for configured object IDs. An account SID on an RDP or SSH segment can use the verified LSA deny baseline below; an approved grant temporarily restores the required right and the host expiry task returns it to deny. Source process and logged-on-user fallback still require an agent gate.</p><div class="lsa-gate-box"><strong>Windows LSA gate</strong><span>{{manageSegment?.lsaBaselines?.length||0}} target baseline(s) enforced</span><label>Change reason<input v-model.trim="lsaReason" minlength="10" maxlength="500" placeholder="Why is this OS logon gate changing?"></label><label class="check-label confirm-checkbox"><input v-model="lsaConfirmation" type="checkbox"> I understand this changes Windows logon rights on target hosts.</label><div class="form-actions"><button type="button" class="button secondary" :disabled="lsaBusy||!manageAccountSid||![22,3389].includes(manageSegment?.port)||lsaReason.length<10||!lsaConfirmation" @click="setLsaBaseline(true)">{{lsaBusy?'Working…':'Enforce on targets'}}</button><button type="button" class="button danger" :disabled="lsaBusy||!manageSegment?.lsaBaselines?.length||lsaReason.length<10||!lsaConfirmation" @click="setLsaBaseline(false)">Restore originals</button></div></div><div class="form-actions"><button class="button primary">Save access policy</button></div></form></GlassWindow>
    <GlassWindow v-model="entraMembersOpen" :title="`Entra group · ${entraMembersSegment?.name||''}`"><div class="form-grid"><p class="muted">Cached Graph members for <span class="mono">{{entraMembersSegment?.entra_group_id}}</span>. Membership expires after five minutes.</p><p v-if="entraSyncBusy" class="muted">Syncing group members…</p><div v-for="member in entraMembers" :key="member.objectId" class="segment-row"><div><strong>{{member.upn||member.email||member.objectId}}</strong><small>{{member.email&&member.upn!==member.email?member.email:''}} · {{member.enabled?'Enabled':'Disabled'}}</small></div></div><p v-if="!entraSyncBusy&&!entraMembers.length" class="empty-side">No user members were returned.</p><div class="form-actions"><button type="button" class="button secondary" @click="entraMembersOpen=false">Close</button></div></div></GlassWindow>
    <GlassWindow v-model="rightsOpen" title="Change Windows logon right"><form class="form-grid" @submit.prevent="changeLogonRight"><label>Windows node<select v-model="rightsForm.nodeId" required><option value="">Select node</option><option v-for="node in nodes.filter(item=>['winrm','winrms'].includes(item.transport)&&item.connection_mode==='agentless')" :key="node.id" :value="node.id">{{node.hostname}}</option></select></label><label>Account SID<input v-model.trim="rightsForm.accountSid" required placeholder="S-1-5-21-…"></label><label>Logon right<select v-model="rightsForm.right"><option v-for="right in logonRightOptions" :key="right" :value="right">{{right}}</option></select></label><label>Action<select v-model="rightsForm.present"><option :value="true">Assign right</option><option :value="false">Remove right</option></select></label><label>Reason<input v-model.trim="rightsForm.reason" required minlength="10" maxlength="500" placeholder="Why is this change needed?"></label><label class="check-label confirm-checkbox"><input v-model="rightsForm.confirmed" type="checkbox"> I understand this changes the selected local LSA assignment.</label><p class="muted">This changes the local LSA assignment on the selected host. Group Policy can overwrite it, and group membership or an explicit deny can affect the effective logon right. Critical system and administrator SIDs are protected.</p><p v-if="unsafeNetworkChange" class="error-msg">This network logon change could block WinRM administration and is unavailable here.</p><div class="form-actions"><button class="button primary" :disabled="rightsBusy||unsafeNetworkChange||!rightsForm.confirmed">{{rightsBusy?'Applying…':'Apply and verify'}}</button></div></form></GlassWindow>
  </div>
</template>

<style scoped>
.rights-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}.rights-actions select{min-width:150px}
.portal-panel{margin-bottom:1rem}.portal-panel p{max-width:900px}.portal-form{grid-template-columns:repeat(auto-fit,minmax(200px,1fr));align-items:end}.portal-form .form-actions{margin:0}.segment-row>div:nth-child(2){flex:1;min-width:0}.segment-actions{display:flex;align-items:center;gap:.4rem;flex-wrap:wrap;justify-content:flex-end}
.portal-brand-header{display:flex;align-items:center;gap:12px;min-width:0}.portal-brand-image{width:58px;height:50px;object-fit:contain;flex:none}
.portal-company-name{display:block;font-size:.75rem;letter-spacing:.03em;color:var(--muted);margin-bottom:3px}
.identity-tabs-shell{overflow:hidden}.identity-tabs{display:flex;align-items:stretch;gap:4px;padding:.55rem .7rem 0;border-bottom:1px solid var(--border);overflow-x:auto}.identity-tabs button{display:inline-flex;align-items:center;gap:.45rem;flex:0 0 auto;border:0;border-bottom:3px solid transparent;background:transparent;color:var(--muted);padding:.8rem 1rem;font:inherit;font-weight:650;cursor:pointer;white-space:nowrap}.identity-tabs button:hover,.identity-tabs button:focus-visible{color:var(--text);background:var(--surface-soft)}.identity-tabs button.active{color:var(--accent,#3864ae);border-bottom-color:var(--accent,#3864ae);background:var(--surface-soft)}.identity-tabs button .count-chip{font-size:.68rem;min-width:1.45rem;padding:.12rem .35rem}.identity-tab-panel{padding:1.15rem;outline:none}.identity-tab-panel:focus-visible{box-shadow:inset 0 0 0 2px color-mix(in srgb,var(--accent,#3864ae) 55%,transparent)}.tab-description{margin:.35rem 0 0;color:var(--muted);font-size:.82rem}.tab-footnote{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-top:1rem;padding:.75rem .9rem;border:1px solid var(--border);border-radius:8px;color:var(--muted);font-size:.8rem}.tab-footnote span{display:flex;align-items:center;gap:.4rem}.challenge-table-wrap{overflow:auto}.challenge-table-wrap table{min-width:820px}.challenge-table-wrap td small{display:block;color:var(--muted);margin-top:.2rem}.challenge-table-wrap td:last-child small{max-width:220px}.request-access-dialog{display:grid;gap:1rem}.request-access-hero{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding-bottom:.8rem;border-bottom:1px solid var(--border)}.request-access-hero h2{margin:0}.request-access-copy{margin:0;color:var(--muted);line-height:1.5}.selected-target{display:grid;gap:.25rem;align-content:center;margin:0;padding:.7rem .8rem;border:1px solid var(--border);border-radius:6px;background:var(--surface-soft)}.selected-target strong{font-size:.9rem}.active-grants{display:grid;gap:.55rem;border-top:1px solid var(--border);padding-top:.9rem}.active-grants .panel-title{margin:0}.active-grants .panel-title h3{margin:0}.learning-section{margin-top:1.25rem}.learning-section h3{margin:0}.learning-section .learning-intro{padding:.45rem 0 .75rem}.learning-section+.learning-section{border-top:1px solid var(--border);padding-top:1.1rem}
.challenge-filters{display:flex;flex-wrap:wrap;gap:.5rem;padding:.75rem 1rem;border-bottom:1px solid var(--border)}
.challenge-filters select,.challenge-filters input{flex:1 1 120px;min-width:0}
.challenge-pages{display:flex;align-items:center;justify-content:space-between;gap:.7rem;padding:.7rem 1rem;border-top:1px solid var(--border);font-size:.8rem}
.challenge-pages>div{display:flex;gap:.5rem}.learning-intro{padding:.8rem 1rem 0;margin:0;color:var(--muted);font-size:.85rem}.learning-search{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:.8rem 1rem}.learning-search input{min-width:min(100%,280px);flex:1}.learning-sid{display:block;font-size:.7rem;color:var(--muted);word-break:break-all}
.lsa-gate-box{grid-column:1/-1;display:grid;gap:.65rem;padding:1rem;border:1px solid var(--border);background:var(--surface-soft)}.lsa-gate-box>span{color:var(--muted);font-size:.8rem}
@media(max-width:720px){.identity-tabs{padding-left:.35rem}.identity-tabs button{padding:.7rem .7rem}.identity-tab-panel{padding:.8rem}.tab-footnote,.request-access-hero{align-items:flex-start;flex-direction:column}.tab-footnote .button{width:100%}.rights-actions{justify-content:flex-start}}
@media(max-width:620px){.challenge-pages{flex-wrap:wrap}.request-access-hero .status{align-self:flex-start}}
</style>
