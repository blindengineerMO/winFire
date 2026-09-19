<script setup>
import {computed} from 'vue'
import {Line,Bar} from 'vue-chartjs'
import {Chart as ChartJS,LineElement,PointElement,BarElement,CategoryScale,LinearScale,Tooltip,Legend} from 'chart.js'

ChartJS.register(LineElement,PointElement,BarElement,CategoryScale,LinearScale,Tooltip,Legend)
const props=defineProps({stats:{type:Object,required:true}})
const verifier=computed(()=>props.stats.verifierTrend||[])
const mfa=computed(()=>props.stats.mfaTrend||[])
const options={responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#aab8c8'}}},scales:{x:{ticks:{color:'#8494a8'},grid:{display:false}},y:{beginAtZero:true,ticks:{color:'#8494a8'},grid:{color:'#26354a'}}}}
const rateOptions={...options,scales:{...options.scales,y:{...options.scales.y,max:100,ticks:{color:'#8494a8',callback:value=>`${value}%`}}}}
</script>

<template>
  <div class="dashboard-grid">
    <section class="panel glass">
      <div class="panel-title"><div><span class="eyebrow">VERIFICATION</span><h2>Pass rate, last 14 days</h2></div></div>
      <div v-if="verifier.length" class="chart-box bar"><Line :data="{labels:verifier.map(day=>day.day),datasets:[{label:'Pass rate',data:verifier.map(day=>day.passRate),borderColor:'#55e8bb',backgroundColor:'#55e8bb',tension:.25}]}" :options="rateOptions" /></div>
      <div v-else class="chart-box bar"><div class="empty-chart"><i class="mdi mdi-chart-timeline-variant"></i><span>No verifier results yet</span></div></div>
    </section>
    <section class="panel glass">
      <div class="panel-title"><div><span class="eyebrow">IDENTITY</span><h2>MFA decisions, last 14 days</h2></div></div>
      <div v-if="mfa.length" class="chart-box bar"><Bar :data="{labels:mfa.map(day=>day.day),datasets:[{label:'Approved',data:mfa.map(day=>day.approved),backgroundColor:'#55e8bb'},{label:'Denied',data:mfa.map(day=>day.denied),backgroundColor:'#ff7985'}]}" :options="options" /></div>
      <div v-else class="chart-box bar"><div class="empty-chart"><i class="mdi mdi-shield-account-outline"></i><span>No MFA decisions yet</span></div></div>
    </section>
  </div>
</template>
