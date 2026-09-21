<script setup>
import {ref,watch} from 'vue'
import GlassWindow from './GlassWindow.vue'
const props=defineProps({modelValue:{type:Boolean,required:true},title:{type:String,default:'Confirm change'},message:{type:String,required:true},confirmLabel:{type:String,default:'Confirm'},busy:{type:Boolean,default:false}})
const emit=defineEmits(['update:modelValue','confirm'])
const checked=ref(false)
watch(()=>props.modelValue,open=>{if(open)checked.value=false})
function close(){emit('update:modelValue',false)}
function confirm(){if(!checked.value||props.busy)return;emit('confirm')}
</script>
<template>
  <GlassWindow :model-value="modelValue" :title="title" width="500px" @update:model-value="emit('update:modelValue',$event)">
    <div class="confirm-dialog">
      <p>{{message}}</p>
      <label class="check-label confirm-checkbox"><input v-model="checked" type="checkbox"> I understand this change may affect access or policy enforcement.</label>
      <div class="form-actions"><button type="button" class="button secondary" @click="close">Cancel</button><button type="button" class="button danger" :disabled="!checked||busy" @click="confirm">{{busy?'Working…':confirmLabel}}</button></div>
    </div>
  </GlassWindow>
</template>
