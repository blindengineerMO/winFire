<script setup>
import {onMounted,onUnmounted,ref,computed,watch,nextTick} from 'vue'
import PolicyGovernance from '../components/policies/PolicyGovernance.vue'
import StagedDeployment from '../components/policies/StagedDeployment.vue'
import PolicySimulation from '../components/policies/PolicySimulation.vue'
import PolicyEditor from '../components/policies/PolicyEditor.vue'
import {nodeLabel,nodeIssue,graphDocument} from '../components/policies/model.js'
import PageHeader from '../components/PageHeader.vue'
import GlassWindow from '../components/GlassWindow.vue'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import LearnedRuleEvidence from '../components/LearnedRuleEvidence.vue'
import {api,session} from '../services/api.js'
import {useRoute,useRouter} from 'vue-router'
const route=useRoute(),router=useRouter()
const policies=ref([]),nodes=ref([]),groups=ref([]),selected=ref(null),versions=ref([]),assignments=ref([]),graphNodes=ref([]),edges=ref([]),formOpen=ref(false),assignOpen=ref(false),historyOpen=ref(false),error=ref(''),message=ref(''),newName=ref(''),newDescription=ref(''),comment=ref(''),assignKind=ref('node'),assignTarget=ref(''),busy=ref(false)
const learningPreview=ref(null),previewBusy=ref(false)
const confirmDialogOpen=ref(false),confirmDialogMessage=ref(''),confirmDialogAction=ref(null),confirmDialogBusy=ref(false)
const targetDropActive=ref(false)
const verifyOpen=ref(false),verifyVantageId=ref(''),verifyBusy=ref(false)
const verifierPeers=computed(()=>nodes.value.filter(node=>['winrm','winrms'].includes(node.transport)))
const policyEditor=ref(null),loadedPolicyId=ref(null),loadingPolicy=ref(false),draftPreview=ref(null),validating=ref(false),draftError=ref(''),draftNotice=ref(''),baseVersionId=ref(null),savedSignature=ref('')
let selectionSequence=0,validationSequence=0,validationTimer
function loadGovernanceDraft(graph){if(!editable.value)return;askConfirmation('Replace the current draft with this reviewed proposal? This does not deploy rules.',()=>{graphNodes.value=graph.nodes;edges.value=graph.edges;draftNotice.value='Review and simulate this proposal before saving or deploying.'})}
const currentGraph=()=>graphDocument(graphNodes.value,edges.value)
const graphSignature=computed(()=>JSON.stringify(currentGraph()))
const dirty=computed(()=>!isLearningPreview.value&&graphSignature.value!==savedSignature.value)
const policyLoaded=computed(()=>!!selected.value&&loadedPolicyId.value===selected.value.id)
const editable=computed(()=>policyLoaded.value&&canEdit.value&&selected.value?.canWrite!==false&&!isLearningPreview.value&&!loadingPolicy.value)
const staleDraft=computed(()=>baseVersionId.value!==(selected.value?.current_version_id||null))
const compareFrom=ref(''),compareTo=ref(''),comparison=ref(null),compareBusy=ref(false)
let resizeTimer,previewTimer
function fit(){clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>policyEditor.value?.fit(),100)}
const isLearningPreview=computed(()=>selected.value?.origin==='learned'&&selected.value?.learning?.status==='active')
const activeRules=computed(()=>isLearningPreview.value?learningPreview.value?.rules||[]:(dirty.value?(validating.value?[]:draftPreview.value?.rules||[]):versions.value.find(v=>v.id===selected.value?.current_version_id)?.rules||[]))
const activeMfaGates=computed(()=>isLearningPreview.value?[]:draftPreview.value?.mfaGates||[])
const evidenceByNode=computed(()=>{
  const graph=isLearningPreview.value?learningPreview.value?.graph:versions.value.find(v=>v.id===selected.value?.current_version_id)?.graph
  return new Map((graph?.nodes||[]).map(node=>[node.id,node.data?.evidence]))
})
function ruleEvidence(rule){return evidenceByNode.value.get(rule.sourceNodeId)}
const canEdit=computed(()=>['owner','admin','editor'].includes(session.user?.role))
function assignmentLabel(assignment){return assignment.node_id?nodes.value.find(node=>node.id===assignment.node_id)?.hostname||assignment.node_id:groups.value.find(group=>group.id===assignment.node_group_id)?.name||assignment.node_group_id}
async function refreshAssignments(){if(selected.value)assignments.value=(await api(`/policies/${selected.value.id}`)).assignments||[]}
const validationIssue=computed(()=>{
  if(!selected.value)return ''
  for(const node of graphNodes.value){const issue=nodeIssue(node);if(issue)return `${nodeLabel(node)}: ${issue}`}
  return ''
})
function storageKey(policy=selected.value){return `winfire_draft_${session.user?.id||'operator'}_${policy?.id}`}
async function load(){try{[policies.value,nodes.value,groups.value]=await Promise.all([api('/policies'),api('/nodes'),api('/node-groups')]);if(selected.value){selected.value=policies.value.find(p=>p.id===selected.value.id)||null}}catch(e){error.value=e.message}}
async function refreshLearningPreview(policy=selected.value){if(!policy||policy.learning?.status!=='active')return;previewBusy.value=true;try{const preview=await api(`/policies/${policy.id}/learning-preview`);if(selected.value?.id!==policy.id)return;learningPreview.value=preview;graphNodes.value=preview.graph.nodes.map(n=>({...n,data:{...n.data,label:nodeLabel(n)}}));edges.value=preview.graph.edges;error.value='';await nextTick();fit()}catch(e){error.value=e.message}finally{previewBusy.value=false}}
async function validateDraft(){
  if(!policyLoaded.value||loadingPolicy.value||isLearningPreview.value)return
  const sequence=++validationSequence,policyId=selected.value.id,signature=graphSignature.value
  validating.value=true;draftError.value=''
  try{const preview=await api(`/policies/${policyId}/preview`,{method:'POST',body:{graph:currentGraph()}});if(sequence===validationSequence&&selected.value?.id===policyId&&signature===graphSignature.value){draftPreview.value=preview;draftError.value=preview.managementIssue||preview.conflicts.map(c=>`${c.rule} conflicts with ${c.otherPolicy} / ${c.otherRule}`).join('; ')}}
  catch(e){if(sequence===validationSequence&&selected.value?.id===policyId&&signature===graphSignature.value){draftError.value=e.message;draftPreview.value=null}}
  finally{if(sequence===validationSequence)validating.value=false}
}
async function choose(policy,{discard=false}={}){
  const sequence=++selectionSequence;++validationSequence;clearTimeout(validationTimer);loadingPolicy.value=true;loadedPolicyId.value=null;graphNodes.value=[];edges.value=[];versions.value=[];assignments.value=[];validating.value=false;selected.value=policy;learningPreview.value=null;draftPreview.value=null;draftError.value='';draftNotice.value='';error.value=''
  try{
    const [history,details]=await Promise.all([api(`/policies/${policy.id}/versions`),api(`/policies/${policy.id}`)])
    if(sequence!==selectionSequence)return
    versions.value=history;assignments.value=details.assignments||[];selected.value={...policy,...details}
    if(route.query.policyId!==policy.id)router.replace({query:{...route.query,policyId:policy.id}})
    compareFrom.value=history[1]?.id||history[0]?.id||'';compareTo.value=details.current_version_id||history[0]?.id||'';comparison.value=null
    baseVersionId.value=details.current_version_id||null
    if(isLearningPreview.value){await refreshLearningPreview(selected.value);if(sequence===selectionSequence&&learningPreview.value)loadedPolicyId.value=policy.id;return}
    const current=history.find(v=>v.id===details.current_version_id)?.graph||{nodes:[],edges:[]}
    savedSignature.value=JSON.stringify(graphDocument(current.nodes,current.edges||[]))
    let graph=current
    if(discard){localStorage.removeItem(storageKey());localStorage.removeItem(`winfire_draft_${policy.id}`)}
    else if(canEdit.value&&selected.value.canWrite!==false){
      try{
        const cached=localStorage.getItem(storageKey())||localStorage.getItem(`winfire_draft_${policy.id}`)
        if(cached){const draft=JSON.parse(cached),candidate=draft.graph||draft;if(!Array.isArray(candidate.nodes)||!Array.isArray(candidate.edges))throw Error('Invalid stored draft');graphDocument(candidate.nodes,candidate.edges);graph=candidate;if('baseVersionId' in draft)baseVersionId.value=draft.baseVersionId;draftNotice.value='Restored your local draft. Review it before saving.'}
      }catch{draftNotice.value='The stored draft could not be read. The saved policy is shown; the stored copy has been retained.'}
    }
    graphNodes.value=graph.nodes.map((n,i)=>({...n,position:n.position||{x:60+(i%3)*310,y:60+Math.floor(i/3)*180},data:{...n.data}}));edges.value=graph.edges;loadedPolicyId.value=policy.id
    await nextTick();policyEditor.value?.resetHistory();fit()
  }catch(e){if(sequence===selectionSequence)error.value=e.message}
  finally{if(sequence===selectionSequence){loadingPolicy.value=false;if(!isLearningPreview.value)validateDraft()}}
}
watch(graphSignature,()=>{
  if(!policyLoaded.value||loadingPolicy.value||isLearningPreview.value)return
  if(editable.value&&dirty.value){try{localStorage.setItem(storageKey(),JSON.stringify({graph:currentGraph(),baseVersionId:baseVersionId.value}))}catch{draftNotice.value='Browser storage is unavailable. Save a version to retain your changes.'}}
  if(editable.value&&!dirty.value){try{localStorage.removeItem(storageKey());localStorage.removeItem(`winfire_draft_${selected.value.id}`)}catch{}}
  clearTimeout(validationTimer);++validationSequence;validating.value=true;validationTimer=setTimeout(validateDraft,450)
})
watch(()=>route.query.policyId,id=>{const policy=policies.value.find(p=>p.id===id);if(policy&&selected.value?.id!==id)choose(policy)})
onMounted(async()=>{await load();const requested=policies.value.find(policy=>policy.id===route.query.policyId)||policies.value[0];if(requested)await choose(requested);window.addEventListener('resize',fit);previewTimer=setInterval(async()=>{if(!isLearningPreview.value)return;const policyId=selected.value.id;await load();if(selected.value?.id!==policyId)return;if(isLearningPreview.value)await refreshLearningPreview();else await choose(selected.value)},60_000)})
onUnmounted(()=>{window.removeEventListener('resize',fit);clearTimeout(resizeTimer);clearInterval(previewTimer);clearTimeout(validationTimer);++selectionSequence;++validationSequence})
async function create(){if(busy.value)return;busy.value=true;error.value='';try{const policy=await api('/policies',{method:'POST',body:{name:newName.value,description:newDescription.value}});formOpen.value=false;newName.value='';newDescription.value='';await load();await choose(policies.value.find(p=>p.id===policy.id)||policy)}catch(e){error.value=e.message}finally{busy.value=false}}
async function save(){
  if(!editable.value||busy.value||staleDraft.value)return
  busy.value=true;error.value=''
  try{
    const policyId=selected.value.id,graph=currentGraph()
    await api(`/policies/${policyId}/versions`,{method:'POST',body:{graph,comment:comment.value,baseVersionId:baseVersionId.value}})
    localStorage.removeItem(storageKey());localStorage.removeItem(`winfire_draft_${policyId}`);comment.value='';loadingPolicy.value=true
    await load();await choose(policies.value.find(p=>p.id===policyId));message.value='Version saved. Apply the saved version or sync it from the top bar.'
  }catch(e){error.value=e.message}finally{busy.value=false;loadingPolicy.value=false}
}
function discardDraft(){askConfirmation('Discard the local draft and load the latest saved version?',()=>choose(selected.value,{discard:true}))}
async function assignTargetToPolicy(kind,target){
  if(!selected.value||!editable.value||busy.value)return
  busy.value=true;error.value='';message.value=''
  try{
    await api(`/policies/${selected.value.id}/assignments`,{method:'POST',body:kind==='node'?{nodeId:target}:{nodeGroupId:target}})
    assignOpen.value=false;assignTarget.value='';await refreshAssignments()
    message.value=kind==='node'?'Node assigned':target==='winfire-global-all-nodes'?'Global policy assigned':'Node group assigned'
  }catch(e){error.value=e.message}
  finally{busy.value=false}
}
async function assign(){await assignTargetToPolicy(assignKind.value,assignKind.value==='global'?'winfire-global-all-nodes':assignTarget.value)}
function dragTarget(event,kind,target){
  if(!editable.value||busy.value){event.preventDefault();return}
  event.dataTransfer.effectAllowed='copy'
  event.dataTransfer.setData('application/x-winfire-target',JSON.stringify({kind,target}))
}
function dropTarget(event){
  targetDropActive.value=false
  if(!editable.value||busy.value)return
  let payload
  try{payload=JSON.parse(event.dataTransfer.getData('application/x-winfire-target'))}catch{return}
  if(payload.kind==='node'&&nodes.value.some(node=>node.id===payload.target))assignTargetToPolicy('node',payload.target)
  else if(payload.kind==='group'&&groups.value.some(group=>group.id===payload.target))assignTargetToPolicy('group',payload.target)
}
function askConfirmation(message,action){confirmDialogMessage.value=message;confirmDialogAction.value=action;confirmDialogOpen.value=true}
async function runConfirmation(){const action=confirmDialogAction.value;confirmDialogOpen.value=false;confirmDialogAction.value=null;if(action){confirmDialogBusy.value=true;try{await action()}finally{confirmDialogBusy.value=false}}}
function removeAssignment(assignment){askConfirmation(`Remove the assignment to ${assignmentLabel(assignment)}? Managed firewall rules will be removed from nodes that no longer have this policy.`,async()=>{
  busy.value=true;error.value='';message.value=''
  try{const result=await api(`/policies/${selected.value.id}/assignments/${assignment.id}`,{method:'DELETE'});await refreshAssignments();message.value=result.queued?'Agent firewall cleanup queued. The assignment will disappear after the agent confirms removal.':`Assignment removed; cleaned ${result.cleanedNodes.length} node(s)`}
  catch(e){error.value=e.message}
  finally{busy.value=false}
})}
async function apply(){busy.value=true;try{const result=await api(`/policies/${selected.value.id}/apply`,{method:'POST',body:{}});message.value=`Applied to ${result.results.filter(r=>r.status==='success').length} node(s); ${result.results.filter(r=>r.status==='queued').length} queued; ${result.results.filter(r=>r.status==='failed').length} failed` }catch(e){error.value=e.message}finally{busy.value=false}}
async function verifyPolicy(){
  if(!selected.value)return
  verifyBusy.value=true;error.value='';message.value=''
  try{
    const result=await api('/verifier/runs',{method:'POST',body:{policyId:selected.value.id,...(verifyVantageId.value?{vantageNodeId:verifyVantageId.value}:{})}})
    verifyOpen.value=false
    const passed=result.results.filter(item=>item.status==='pass').length,failed=result.results.filter(item=>item.status==='fail').length
    message.value=`Verification complete: ${passed} passed, ${failed} failed, ${result.results.length-passed-failed} inconclusive. See Reports → Verification for evidence.`
    await load()
  }catch(cause){error.value=cause.message}
  finally{verifyBusy.value=false}
}
async function recall(version){busy.value=true;try{await api(`/policies/${selected.value.id}/versions/${version.id}/recall`,{method:'POST',body:{}});historyOpen.value=false;message.value=`Recalled version ${version.version_no}. Sync it from the top bar.`;await load();await choose(selected.value,{discard:true})}catch(e){error.value=e.message}finally{busy.value=false}}
async function compareVersions(){compareBusy.value=true;comparison.value=null;error.value='';try{comparison.value=await api(`/policies/${selected.value.id}/diff?from=${encodeURIComponent(compareFrom.value)}&to=${encodeURIComponent(compareTo.value)}`)}catch(e){error.value=e.message}finally{compareBusy.value=false}}
function describeRule(rule){return `${rule.name}: ${rule.action} ${rule.direction} ${rule.protocol} local ${rule.localPort||'Any'} / remote ${rule.remotePort||'Any'} / ${rule.remoteAddress||'Any'}`}
function describeNode(node){return `${nodeLabel(node)} (${node.type})`}
</script>
<template>
<div class="view">
<PageHeader eyebrow="POLICY / AUTHORING" title="Policy studio" description="Compose, version and apply Windows Firewall rules">
<button v-if="canEdit" class="button primary" @click="formOpen=true">
<i class="mdi mdi-plus">
</i> New policy</button>
</PageHeader>
<div v-if="error" class="error-msg">{{error}}</div>
<div v-if="message" class="success-msg">{{message}}</div>
<div class="studio-layout">
<aside class="panel glass policy-list" aria-label="Policy library">
<div class="panel-title">
<div>
<span class="eyebrow">LIBRARY</span>
<h2>Policies</h2>
</div>
<span class="count-chip">{{policies.length}}</span>
</div>
<button v-for="policy in policies" :key="policy.id" :title="policy.name" :disabled="busy" class="policy-item" :class="{active:selected?.id===policy.id}" @click="choose(policy)">
<i class="mdi mdi-shield-outline">
</i>
<span>
<strong>{{policy.name}}</strong>
<small>{{policy.origin==='learned'?`Personal · ${policy.learning?.status||'ready'}`:`Version ${policy.version_no||'draft'}`}}</small>
</span>
<span class="status" :class="policy.learning?.status==='active'?'learning':policy.verificationStatus||'unknown'">{{policy.learning?.status==='active'?'Learning':policy.verificationStatus||'Unchecked'}}</span>
<i class="mdi mdi-chevron-right">
</i>
</button>
<div v-if="!policies.length" class="empty-side">Create a policy to start building rules.</div>
</aside>
<div v-if="selected" class="studio-main">
<section class="panel glass canvas-panel">
<div class="panel-title studio-title">
<div>
<span class="eyebrow">{{isLearningPreview?'LIVE LEARNING PREVIEW':'VISUAL POLICY EDITOR'}}</span>
<h2>{{selected.name}}</h2>
</div>
<div class="inline-actions">
<button class="button small secondary" :disabled="!policyLoaded" @click="historyOpen=true">
<i class="mdi mdi-history">
</i> History</button>
<button v-if="policyLoaded&&!isLearningPreview&&canEdit" class="button small secondary" @click="verifyOpen=true">
<i class="mdi mdi-radar">
</i> Verify</button>
<button v-if="editable" class="button small secondary" @click="assignOpen=true">
<i class="mdi mdi-link-variant">
</i> Assign</button>
<button v-if="editable&&['owner','admin'].includes(session.user?.role)" class="button small secondary" :disabled="busy||dirty||!selected.current_version_id" @click="askConfirmation('Apply the saved policy version to its assigned nodes? This changes their firewall rules.',apply)">
<i class="mdi mdi-send-outline">
</i> Apply</button>
</div>
</div>
<div v-if="isLearningPreview" class="learning-preview-summary">
<div>
<strong>{{learningPreview?.rules.length||0}} proposed rules</strong>
<span>{{learningPreview?.newFlowCount||0}} new rules · {{learningPreview?.observedFlowCount||0}} observed 5-tuples</span>
<small>Training ends {{new Date(selected.learning.ends_at).toLocaleString()}}<template v-if="learningPreview?.progressiveEnabled"> · next progressive apply {{new Date(learningPreview.nextProgressiveAt).toLocaleString()}}</template>
</small>
</div>
<button class="button small secondary" :disabled="previewBusy" @click="refreshLearningPreview()">{{previewBusy?'Refreshing…':'Refresh preview'}}</button>
</div>
<p v-if="loadingPolicy" class="editor-notice" role="status">Loading policy…</p>
<p v-if="isLearningPreview" class="editor-notice">Automatic learning owns this policy until training ends. Both editors are available for inspecting rules and connections.</p>
<p v-else-if="policyLoaded&&!editable" class="editor-notice">You have read-only access to this policy.</p>
<p v-if="draftNotice" class="editor-notice" role="status">{{draftNotice}}</p>
<p v-if="policyLoaded&&staleDraft&&!isLearningPreview" class="error-msg" role="alert">This draft is based on an older version. Use History to review changes, then discard the draft to load the latest saved version.</p>
<p v-if="!loadingPolicy&&!policyLoaded" class="editor-notice">The policy could not be loaded. <button class="button small secondary" @click="choose(selected)">Retry</button></p>
<PolicyEditor v-if="policyLoaded&&!loadingPolicy" :key="selected.id" ref="policyEditor" v-model:nodes="graphNodes" v-model:edges="edges" :policy-id="selected.id" :readonly="!editable||busy" :rules="activeRules" />
<div v-if="editable" class="canvas-footer">
<input v-model="comment" placeholder="Version comment (optional)" aria-label="Version comment">
<span class="hint">{{dirty?'Unsaved changes · local draft':'Saved version'}}</span>
<button class="button small secondary" :disabled="busy||(!dirty&&!staleDraft)" @click="discardDraft">Discard draft</button>
<span v-if="validationIssue" class="validation-hint" role="alert">{{validationIssue}}</span>
<button class="button primary" :disabled="busy||validating||!!validationIssue||!!draftError||!draftPreview?.canSave||staleDraft" @click="save">
<i class="mdi mdi-content-save-outline">
</i> Save version</button>
</div>
<p v-if="draftError" class="error-msg" role="alert">{{draftError}}</p>
<p v-for="warning in draftPreview?.warnings||[]" :key="warning" class="editor-notice">{{warning}}</p>
</section>
<PolicyGovernance v-if="policyLoaded&&!isLearningPreview" :key="'governance-'+selected.id" :policy="selected" :rules="activeRules" :editable="editable&&!dirty" @draft="loadGovernanceDraft"/>
<StagedDeployment v-if="policyLoaded&&!isLearningPreview" :key="'staging-'+selected.id" :policy="selected"/>
<PolicySimulation v-if="policyLoaded&&!isLearningPreview" :key="selected.id" :policy="selected" :graph="currentGraph()" :base-version-id="baseVersionId" :nodes="nodes" :editable="editable"/>
<section v-if="policyLoaded" class="panel glass rules-panel">
<div class="panel-title">
<div>
<span class="eyebrow">COMPILED OUTPUT</span>
<h2>{{activeRules.length}} {{isLearningPreview?'proposed':dirty?'draft':'saved'}} rules</h2>
</div>
</div>
<div v-if="activeMfaGates.length" class="mfa-gate-summary">
<div v-for="gate in activeMfaGates" :key="gate.id" class="rule-row">
<span class="status unknown">MFA gate</span>
<strong>{{gate.name}}</strong>
<span>TCP {{gate.targetPort}} · session {{gate.sessionTtlMinutes}}m · reactive {{gate.reactiveTtlMinutes}}m</span>
<span v-if="gate.entraGroupId" class="mono">Entra {{gate.entraGroupId}}</span>
<small>Staged metadata; deployment waits for the Windows challenge broker.</small>
</div>
</div>
<div v-if="!activeRules.length&&!activeMfaGates.length" class="empty-side">{{isLearningPreview?'No eligible traffic has been learned yet.':validating?'Validating draft with the API…':draftError?'Resolve the validation error to preview compiled rules.':'No compiled rules in this policy.'}}</div>
<div v-for="rule in activeRules" :key="rule.sourceNodeId" class="rule-row">
<span class="status" :class="rule.action">{{rule.action}}</span>
<strong>{{rule.name}}</strong>
<span>{{rule.direction}} / {{rule.protocol}} / local {{rule.localPort}} / remote {{rule.remotePort||'Any'}}</span>
<span class="mono">{{rule.remoteAddress}}</span>
<span v-if="rule.localUserSid" class="mono">Account {{rule.localUserSid}}</span>
<LearnedRuleEvidence v-if="ruleEvidence(rule)" :evidence="ruleEvidence(rule)" />
</div>
</section>
<section class="panel glass assignments-panel" :class="{'target-drop-active':targetDropActive}" @dragover.prevent="targetDropActive=true" @dragleave="targetDropActive=false" @drop.prevent="dropTarget">
<div class="panel-title">
<div>
<span class="eyebrow">TARGETS</span>
<h2>Assignments</h2>
</div>
<span class="count-chip">{{assignments.length}}</span>
</div>
<div v-if="editable" class="assignment-targets">
<p>Drag a node or group here, or select one below to assign it.</p>
<button v-for="node in nodes.filter(item=>!assignments.some(assignment=>assignment.node_id===item.id))" :key="`node-${node.id}`" type="button" class="assignment-target-chip" draggable="true" :disabled="busy" @dragstart="dragTarget($event,'node',node.id)" @click="assignTargetToPolicy('node',node.id)">
<i class="mdi mdi-server">
</i> {{node.hostname}}</button>
<button v-for="group in groups.filter(item=>!assignments.some(assignment=>assignment.node_group_id===item.id))" :key="`group-${group.id}`" type="button" class="assignment-target-chip" draggable="true" :disabled="busy" @dragstart="dragTarget($event,'group',group.id)" @click="assignTargetToPolicy('group',group.id)">
<i class="mdi mdi-server-network">
</i> {{group.name}}</button>
</div>
<p v-if="!assignments.length" class="empty-side">No nodes or groups assigned yet.</p>
<div v-for="assignment in assignments" :key="assignment.id" class="assignment-row">
<span>
<i class="mdi" :class="assignment.node_id?'mdi-server':'mdi-server-network'">
</i> {{assignmentLabel(assignment)}} <small>{{assignment.node_id?'Node':'Group'}}</small>
</span>
<button v-if="editable" class="button small secondary" :disabled="busy||!!assignment.removal_job_id" :aria-label="`Remove assignment to ${assignmentLabel(assignment)}`" @click="removeAssignment(assignment)">{{assignment.removal_job_id?'Removal queued':'Remove'}}</button>
</div>
</section>
</div>
<section v-else class="panel glass studio-empty">
<i class="mdi mdi-source-branch">
</i>
<h2>Select a policy</h2>
<p>Choose an existing policy or create one to open the visual editor.</p>
</section>
</div>
<GlassWindow v-model="formOpen" title="New policy">
<form class="form-grid" @submit.prevent="create">
<label>Policy name<input v-model="newName" required placeholder="Production RDP access">
</label>
<label>Description<textarea v-model="newDescription" placeholder="What this policy controls">
</textarea>
</label>
<div class="form-actions">
<p v-if="error" class="error-msg" role="alert">{{error}}</p><button class="button primary" :disabled="busy">{{busy?'Creating…':'Create policy'}}</button>
</div>
</form>
</GlassWindow>
<GlassWindow v-model="assignOpen" title="Assign policy">
<div class="form-grid">
<label>Target type<select v-model="assignKind" @change="assignTarget=''">
<option value="node">Node</option>
<option value="group">Node group</option>
<option value="global">All nodes (global)</option>
</select>
</label>
<label v-if="assignKind==='node'">Node<select v-model="assignTarget">
<option value="">Select a node</option>
<option v-for="node in nodes" :key="node.id" :value="node.id">{{node.hostname}}</option>
</select>
</label>
<label v-else-if="assignKind==='group'">Node group<select v-model="assignTarget">
<option value="">Select a group</option>
<option v-for="group in groups.filter(item=>item.id!=='winfire-global-all-nodes')" :key="group.id" :value="group.id">{{group.name}}</option>
</select>
</label>
<p v-else>Apply this policy to every node, including nodes added later.</p>
<div class="form-actions">
<button class="button primary" :disabled="assignKind!=='global'&&!assignTarget" @click="assign">Assign</button>
</div>
</div>
</GlassWindow>
<GlassWindow v-model="verifyOpen" title="Verify policy" width="520px">
<form class="form-grid" @submit.prevent="verifyPolicy">
<p>Probe inbound TCP rules from the control plane or from a managed Windows peer. The peer uses its assigned WinRM credential and does not change firewall rules.</p>
<label>Probe from<select v-model="verifyVantageId">
<option value="">Control plane server</option>
<option v-for="node in verifierPeers" :key="node.id" :value="node.id">{{node.hostname}}</option>
</select>
</label>
<p v-if="verifyVantageId" class="hint">Checks against the peer itself will be inconclusive; select another peer to test that node.</p>
<div class="form-actions">
<button type="button" class="button secondary" @click="verifyOpen=false">Cancel</button>
<button class="button primary" :disabled="verifyBusy">{{verifyBusy?'Verifying…':'Run verification'}}</button>
</div>
</form>
</GlassWindow>
<GlassWindow v-model="historyOpen" title="Version history">
<div v-for="version in versions" :key="version.id" class="history-row">
<div>
<strong>Version {{version.version_no}}</strong>
<small>{{version.comment||'No comment'}} · {{new Date(version.created_at).toLocaleString()}}</small>
</div>
<button class="button small secondary" :disabled="busy||!editable||version.id===selected?.current_version_id" @click="askConfirmation(`Recall version ${version.version_no}? The current local draft will be discarded.`,()=>recall(version))">Recall</button>
</div>
<div v-if="!versions.length" class="empty-side">No saved versions yet.</div>
<div v-if="versions.length>1" class="form-grid" style="margin-top:1rem">
<h3>Compare versions</h3>
<label>From<select v-model="compareFrom" @change="comparison=null">
<option v-for="version in versions" :key="version.id" :value="version.id">Version {{version.version_no}}</option>
</select>
</label>
<label>To<select v-model="compareTo" @change="comparison=null">
<option v-for="version in versions" :key="version.id" :value="version.id">Version {{version.version_no}}</option>
</select>
</label>
<button class="button secondary" :disabled="compareBusy||!compareFrom||!compareTo||compareFrom===compareTo" @click="compareVersions">Show changes</button>
</div>
<div v-if="comparison" class="version-diff" aria-live="polite">
<h3>Version {{comparison.from.versionNo}} → {{comparison.to.versionNo}}</h3>
<h4>Canvas nodes</h4>
<ul>
<li v-for="node in comparison.graph.addedNodes" :key="`added-${node.id}`">Added {{describeNode(node)}}</li>
<li v-for="node in comparison.graph.removedNodes" :key="`removed-${node.id}`">Removed {{describeNode(node)}}</li>
<li v-for="change in comparison.graph.changedNodes" :key="`changed-${change.after.id}`">Changed {{describeNode(change.after)}}<details>
<summary>Show fields</summary>
<pre>Before: {{JSON.stringify({position:change.before.position,data:change.before.data},null,2)}}
After: {{JSON.stringify({position:change.after.position,data:change.after.data},null,2)}}</pre>
</details>
</li>
</ul>
<h4>Connections</h4>
<ul>
<li v-for="edge in comparison.graph.addedEdges" :key="`added-${edge.source}-${edge.target}`">Added {{edge.source}} → {{edge.target}}</li>
<li v-for="edge in comparison.graph.removedEdges" :key="`removed-${edge.source}-${edge.target}`">Removed {{edge.source}} → {{edge.target}}</li>
</ul>
<h4>Compiled firewall rules</h4>
<ul>
<li v-for="rule in comparison.added" :key="`added-${rule.sourceNodeId}`">Added {{describeRule(rule)}}</li>
<li v-for="rule in comparison.removed" :key="`removed-${rule.sourceNodeId}`">Removed {{describeRule(rule)}}</li>
</ul>
<p v-if="!comparison.graph.addedNodes.length&&!comparison.graph.removedNodes.length&&!comparison.graph.changedNodes.length&&!comparison.graph.addedEdges.length&&!comparison.graph.removedEdges.length&&!comparison.added.length&&!comparison.removed.length">No changes between these versions.</p>
</div>
</GlassWindow>
<ConfirmDialog v-model="confirmDialogOpen" :message="confirmDialogMessage" :busy="confirmDialogBusy" @confirm="runConfirmation" />
</div>
</template>

<style scoped>
.editor-notice{padding:10px 16px;font-size:12px;color:var(--muted);margin:0}.studio-main{min-width:0}.studio-title{flex-wrap:wrap;gap:10px}.studio-title h2{overflow-wrap:anywhere}.policy-item strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.canvas-footer{flex-wrap:wrap}.canvas-footer .hint{font-size:11px}.canvas-footer .validation-hint{flex-basis:100%}.studio-layout{grid-template-columns:minmax(180px,240px) minmax(0,1fr)}@media(max-width:1000px){.studio-layout{grid-template-columns:1fr}.policy-list{max-height:260px;overflow:auto}}

.learning-preview-summary{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.8rem 1rem;border-bottom:1px solid var(--border);background:color-mix(in srgb,var(--cyan) 9%,transparent)}
.learning-preview-summary>div{display:grid;gap:.25rem;min-width:0}.learning-preview-summary strong{font-size:.8rem}.learning-preview-summary span,.learning-preview-summary small{font-size:.7rem;color:var(--muted);overflow-wrap:anywhere}.learning-preview-summary .button{flex:none}
@media(max-width:650px){.learning-preview-summary{align-items:flex-start;flex-direction:column}}
.assignments-panel{padding-bottom:.5rem}
.assignments-panel.target-drop-active{outline:2px dashed var(--green);outline-offset:-4px}
.assignment-targets{display:flex;flex-wrap:wrap;gap:.45rem;padding:.8rem 1rem;border-top:1px solid var(--border)}
.assignment-targets p{flex-basis:100%;margin:0 0 .2rem;color:var(--muted);font-size:.75rem}
.assignment-target-chip{display:inline-flex;align-items:center;gap:.35rem;border:1px solid var(--border);border-radius:5px;background:var(--panel);color:var(--field-value);padding:.4rem .55rem;font:inherit;font-size:.72rem;cursor:grab;max-width:100%;overflow-wrap:anywhere}
.assignment-target-chip:focus-visible{outline:2px solid var(--green)}
.assignment-target-chip[aria-disabled="true"]{opacity:.5;cursor:default}
.assignment-row{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.75rem 1rem;border-top:1px solid var(--border)}
.assignment-row span{display:flex;align-items:center;gap:.5rem;min-width:0;overflow-wrap:anywhere}
.assignment-row small{color:var(--muted)}
.assignment-row .button{flex:none}
.version-diff{margin-top:1rem;border-top:1px solid var(--border);padding-top:.5rem;overflow-wrap:anywhere}
.version-diff h4{margin:.9rem 0 .3rem;font-size:.8rem;color:var(--muted)}
.version-diff ul{margin:.3rem 0;padding-left:1.35rem;line-height:1.5}
.version-diff li{margin:.3rem 0}
.version-diff pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.7rem}
.version-diff summary{cursor:pointer}
.validation-hint{color:#ffb99f;font-size:.75rem;max-width:22rem;line-height:1.3}
</style>
