<script setup>
import ConfirmDialog from './dialogs/ConfirmDialog.vue'
defineOptions({inheritAttrs:false})
</script>
<template><ConfirmDialog v-bind="$attrs" /></template>
