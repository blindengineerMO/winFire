<script setup>
import {onMounted,ref,watch} from 'vue'
import {api} from '../lib/api.js'

const props=defineProps({nodes:{type:Array,required:true},groups:{type:Array,required:true}})
const settings=ref({defaultPollSeconds:30,defaultChannelMode:'pull',overrides:[]})
const targetType=ref('node'),targetId=ref(''),pollSeconds=ref(30),channelMode=ref('pull'),busy=ref(false),error=ref(''),message=ref('')
watch(targetType,()=>{targetId.value=''})
async function load(){try{settings.value=await api('/settings/agent-poll');error.value=''}catch(cause){error.value=cause.message}}
async function save(value){
  busy.value=true;error.value='';message.value=''
  try{
    settings.value=await api('/settings/agent-poll',{method:'PUT',body:{targetType:value?.targetType||targetType.value,targetId:value?.targetId||targetId.value,pollSeconds:value?null:Number(pollSeconds.value),channelMode:value?'pull':channelMode.value}})
    message.value=value?'Agent channel override removed':'Agent channel settings saved. The agent will receive them at its next heartbeat.'
  }catch(cause){error.value=cause.message}
  finally{busy.value=false}
}
onMounted(load)
</script>

<template>
  <div class="agent-poll-settings">
    <h3>Agent polling</h3>
    <p>The default job channel is {{settings.defaultChannelMode}} with a {{settings.defaultPollSeconds}} second pull interval. A node setting takes priority over group settings; when groups differ, push wins so jobs can be delivered immediately. Push uses the existing mutually authenticated single-port connection.</p>
    <form class="poll-form" @submit.prevent="save()">
      <label>Target type<select v-model="targetType"><option value="node">Node</option><option value="group">Node group</option></select></label>
      <label>Target<select v-model="targetId" required><option value="">Select a {{targetType==='node'?'node':'group'}}</option><option v-for="item in targetType==='node'?props.nodes:props.groups" :key="item.id" :value="item.id">{{targetType==='node'?item.hostname:item.name}}</option></select></label>
      <label>Poll every (seconds)<input v-model.number="pollSeconds" type="number" min="15" max="300" required></label>
      <label>Job channel<select v-model="channelMode"><option value="pull">Pull (scheduled)</option><option value="push">Push (live stream)</option></select></label>
      <button type="submit" class="button small secondary" :disabled="busy||!targetId">Save channel</button>
    </form>
    <p v-if="error" class="error-msg" role="alert">{{error}}</p><p v-if="message" class="success-msg" role="status">{{message}}</p>
    <div v-for="item in settings.overrides" :key="`${item.targetType}:${item.targetId}`" class="poll-row"><span>{{item.targetName}} <small>{{item.targetType}} · {{item.channelMode}} · {{item.pollSeconds}} seconds</small></span><button type="button" class="button small secondary" :disabled="busy" :aria-label="`Remove agent channel override for ${item.targetName}`" @click="save(item)">Use inherited channel</button></div>
  </div>
</template>

<style scoped>
.agent-poll-settings{margin-top:1.25rem;padding-top:1rem;border-top:1px solid var(--border)}
.agent-poll-settings p{font-size:.82rem;line-height:1.5}
.poll-form{display:flex;align-items:end;gap:.6rem;flex-wrap:wrap;margin:1rem 0}
.poll-form label{display:grid;gap:.3rem;font-size:.72rem;min-width:10rem}
.poll-form input{width:9rem}
.poll-row{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.55rem 0;border-top:1px solid var(--border);font-size:.78rem}
.poll-row small{display:block;color:var(--muted);margin-top:.2rem}
</style>
