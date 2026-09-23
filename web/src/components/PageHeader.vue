<script setup>defineProps({eyebrow:String,title:String,description:String})</script>
<template><div v-if="$slots.default" class="page-heading page-heading-actions" :aria-label="title"><div class="page-actions"><slot /></div></div></template>
