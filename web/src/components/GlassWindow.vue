<script setup>
import {ref} from 'vue'
import {useDraggable} from '@vueuse/core'
const props=defineProps({title:{type:String,required:true},modelValue:{type:Boolean,required:true},width:{type:String,default:'640px'}})
const emit=defineEmits(['update:modelValue'])
const handle=ref(null),windowEl=ref(null),maximized=ref(false)
useDraggable(windowEl,{handle,preventDefault:true})
const close=()=>emit('update:modelValue',false)
</script>
<template>
  <div v-if="modelValue" class="window-backdrop" @click.self="close"><section ref="windowEl" class="glass-window glass" :class="{maximized}" :style="{'--window-width':width}" role="dialog" aria-modal="true" :aria-label="title">
    <header ref="handle" class="window-title"><div class="traffic"><button class="close" @click="close" aria-label="Close"></button><button class="minimize" @click="close" aria-label="Minimize"></button><button class="maximize" @click="maximized=!maximized" aria-label="Maximize"></button></div><strong>{{title}}</strong><span class="window-grip"><i class="mdi mdi-drag"></i></span></header>
    <div class="window-content"><slot /></div>
  </section></div>
</template>
