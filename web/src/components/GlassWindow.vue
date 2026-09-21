<script setup>
import {nextTick,onMounted,ref,watch} from 'vue'
import {useDraggable} from '@vueuse/core'
const props=defineProps({title:{type:String,required:true},modelValue:{type:Boolean,required:true},width:{type:String,default:'640px'}})
const emit=defineEmits(['update:modelValue'])
const handle=ref(null),windowEl=ref(null),maximized=ref(false)
const previouslyFocused=ref(null)
useDraggable(windowEl,{handle,preventDefault:true})
const close=()=>emit('update:modelValue',false)
function focusables(){return [...(windowEl.value?.querySelectorAll('button:not([disabled]),a[href],input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')||[])].filter(item=>item.offsetParent!==null)}
function onKeydown(event){
  if(event.key==='Escape'){event.preventDefault();close();return}
  if(event.key!=='Tab')return
  const items=focusables();if(!items.length){event.preventDefault();return}
  const first=items[0],last=items[items.length-1]
  if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus()}
  else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus()}
}
async function focusWindow(){await nextTick();windowEl.value?.focus()}
watch(()=>props.modelValue,async open=>{
  if(open){previouslyFocused.value=document.activeElement;await focusWindow()}
  else if(previouslyFocused.value&&typeof previouslyFocused.value.focus==='function'){previouslyFocused.value.focus();previouslyFocused.value=null}
})
onMounted(()=>{if(props.modelValue)focusWindow()})
</script>
<template>
  <div v-if="modelValue" class="window-backdrop" @click.self="close"><section ref="windowEl" class="glass-window glass" :class="{maximized}" :style="{'--window-width':width}" role="dialog" aria-modal="true" :aria-label="title" tabindex="-1" @keydown="onKeydown">
    <header ref="handle" class="window-title"><div class="traffic"><button class="close" @click="close" aria-label="Close"></button><button class="minimize" @click="close" aria-label="Minimize"></button><button class="maximize" @click="maximized=!maximized" aria-label="Maximize"></button></div><strong>{{title}}</strong><span class="window-grip"><i class="mdi mdi-drag"></i></span></header>
    <div class="window-content"><slot /></div>
  </section></div>
</template>
