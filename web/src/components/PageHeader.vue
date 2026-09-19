<script setup>defineProps({eyebrow:String,title:String,description:String})</script>
<template><div class="page-heading"><div><span class="eyebrow">{{eyebrow}}</span><h1>{{title}}</h1><p>{{description}}</p></div><div class="page-actions"><slot /></div></div></template>
