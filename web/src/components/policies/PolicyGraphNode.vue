<script setup>
import {computed} from 'vue'
import {Handle,Position} from '@vue-flow/core'
import {types,nodeLabel,scopeTypes,ruleTypes} from './model.js'
const props=defineProps({id:String,type:String,data:Object,selected:Boolean,connectable:Boolean})
const emit=defineEmits(['details'])
const definition=computed(()=>types.find(t=>t[0]===props.type))
const summary=computed(()=>{
 const d=props.data
 if(ruleTypes.includes(props.type))return `${d.direction==='out'?'Outbound':'Inbound'} · ${d.protocol||'TCP'} · ${d.direction==='out'?d.remotePort||'Any':d.localPort||'Any'}`
 return props.type==='portGroup'?d.ports:props.type==='addressGroup'?d.addresses:props.type==='profile'?d.profile:props.type==='schedule'?`${d.start||d.startTime}–${d.end||d.endTime} · ${d.timezone}`:`MFA · TCP ${d.targetPort||d.localPort}`
})
</script>
<template><article class="policy-node" :class="[type,{chosen:selected}]">
  <Handle v-if="type!=='mfaGate'" type="target" :position="Position.Left" :connectable="connectable" :aria-label="`Input to ${nodeLabel(props)}`" />
  <header><i class="mdi" :class="`mdi-${definition?.[1]||'shield-outline'}`" aria-hidden="true"></i><span>{{definition?.[2]||type}}</span></header>
  <button class="node-name nodrag" type="button" @click.stop="emit('details',id)">{{nodeLabel(props)}}</button>
  <p>{{summary}}</p><small v-if="ruleTypes.includes(type)">{{data.remoteAddress||'Any address'}}</small>
  <small v-if="type==='mfaGate'">Metadata · deployment requires broker</small>
  <Handle v-if="scopeTypes.includes(type)" type="source" :position="Position.Right" :connectable="connectable" :aria-label="`Output from ${nodeLabel(props)}`" />
</article></template>
<style scoped>
.policy-node{width:250px;background:var(--panel);color:var(--field-value);border:1px solid var(--border);border-left:4px solid var(--cyan);border-radius:6px;padding:12px;box-shadow:0 2px 5px #0001}.policy-node.allow,.policy-node.program{border-left-color:var(--green)}.policy-node.deny{border-left-color:var(--red,#ce5362)}.policy-node.chosen{outline:2px solid var(--cyan);outline-offset:2px}.policy-node header{display:flex;gap:7px;align-items:center;color:var(--muted);font-size:11px;margin-bottom:7px}.node-name{display:block;text-align:left;border:0;background:none;padding:0;color:inherit;font:inherit;font-size:13px;font-weight:700;cursor:pointer;max-width:100%;overflow-wrap:anywhere}.policy-node p,.policy-node small{display:block;margin:6px 0 0;font-size:11px;overflow-wrap:anywhere}.policy-node small{color:var(--muted)}.policy-node :deep(.vue-flow__handle){width:12px;height:12px;background:var(--cyan);border:2px solid var(--panel)}
</style>
