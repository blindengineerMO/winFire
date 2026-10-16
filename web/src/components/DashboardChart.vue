<script setup>
import {Doughnut,Bar} from 'vue-chartjs'
import {Chart as ChartJS,ArcElement,BarElement,CategoryScale,LinearScale,Tooltip,Legend} from 'chart.js'
defineProps({kind:{type:String,required:true},coverageSummary:{type:Object,default:()=>({assigned:0,uncovered:0})},deniedPorts:{type:Array,default:()=>[]}})
const chartAccessibility={id:'winfire-chart-accessibility',afterInit(chart,_args,options){chart.canvas.setAttribute('aria-label',options?.label||'Data chart')}}
ChartJS.register(ArcElement,BarElement,CategoryScale,LinearScale,Tooltip,Legend,chartAccessibility)
const donutOptions={responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#aab8c8',boxWidth:10}},'winfire-chart-accessibility':{label:'Fleet policy coverage chart'}},cutout:'75%'}
const barOptions={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},'winfire-chart-accessibility':{label:'Top denied ports chart'}},scales:{x:{ticks:{color:'#8494a8'},grid:{display:false}},y:{ticks:{color:'#8494a8'},grid:{color:'#26354a'}}}}
</script>
<template>
  <Doughnut v-if="kind==='coverage'" aria-label="Fleet policy coverage chart" :data="{labels:['Policy assigned','Uncovered'],datasets:[{data:[coverageSummary.assigned,coverageSummary.uncovered],backgroundColor:['#55e8bb','#27374d'],borderWidth:0}]}" :options="donutOptions" />
  <Bar v-else aria-label="Top denied ports chart" :data="{labels:deniedPorts.map(x=>x.dst_port||'Unknown'),datasets:[{data:deniedPorts.map(x=>x.count),backgroundColor:'#8a87fa',borderRadius:4}]}" :options="barOptions" />
</template>
