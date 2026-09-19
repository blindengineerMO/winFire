<script setup>
import {computed} from 'vue'
const props=defineProps({stats:{type:Object,required:true},coverage:{type:Array,required:true}})
const assigned=computed(()=>props.coverage.filter(node=>node.policy_count>0).length)
const uncovered=computed(()=>props.coverage.length-assigned.value)
const drift=computed(()=>props.coverage.filter(node=>node.drift_status==='drift').length)
const assignedPct=computed(()=>props.stats.totalNodes?Math.round(assigned.value/props.stats.totalNodes*100):0)
const uncoveredPct=computed(()=>props.stats.totalNodes?100-assignedPct.value:0)
const reachablePct=computed(()=>props.stats.totalNodes?Math.round(props.stats.reachableNodes/props.stats.totalNodes*100):0)
</script>

<template>
  <section class="enterprise-overview">
    <h2>System Overview</h2>
    <div class="enterprise-flow">
      <div class="enterprise-flow-assets">
        <router-link to="/inventory" class="enterprise-flow-tile"><strong>{{stats.totalNodes}}</strong><span>Managed assets</span><i class="mdi mdi-server-network"></i></router-link>
        <router-link to="/inventory" class="enterprise-flow-tile"><strong>{{stats.reachableNodes}}</strong><span>Reachable assets</span><i class="mdi mdi-lan-connect"></i></router-link>
        <router-link to="/admin" class="enterprise-flow-tile"><strong>{{stats.agentsOnline}}</strong><span>Agents online</span><i class="mdi mdi-desktop-classic"></i></router-link>
      </div>
      <div class="enterprise-flow-progress">
        <router-link to="/reports" class="enterprise-flow-tile"><span>Network<br>segmentation</span><strong class="enterprise-green">{{assignedPct}}% covered</strong><div class="enterprise-progress"><span :style="{width:`${assignedPct}%`}"></span></div></router-link>
        <router-link to="/reports" class="enterprise-flow-tile"><span>Verification</span><strong class="enterprise-green">{{stats.verifierPassRate===null?'No checks':`${stats.verifierPassRate}% passed`}}</strong><div class="enterprise-progress"><span :style="{width:`${stats.verifierPassRate||0}%`}"></span></div></router-link>
        <router-link to="/policies" class="enterprise-flow-tile"><span>Firewall policies</span><strong>{{stats.policies}} policies</strong><i class="mdi mdi-shield-check-outline"></i></router-link>
      </div>
      <div class="enterprise-flow-outcomes">
        <div class="enterprise-outcome enterprise-outcome-good"><h3>Protected</h3><div><strong>{{assigned}} assets</strong><span>Policy assigned</span></div><div><strong>{{stats.compliantNodes}} assets</strong><span>Compliant</span></div></div>
        <div class="enterprise-outcome enterprise-outcome-risk"><h3>Risks</h3><div><strong>{{uncovered}} assets</strong><span>Missing policy</span></div><div><strong>{{drift}} assets</strong><span>Observed drift</span></div></div>
      </div>
      <div class="enterprise-flow-breakdown"><h3>Risk Breakdown &amp; Fix</h3><div><strong>{{uncovered}} assets</strong><span>Not covered</span><router-link to="/inventory">Review</router-link></div><div><strong>{{drift}} assets</strong><span>Drift detected</span><router-link to="/reports">Review</router-link></div><div><strong>{{stats.failedApplies}} runs</strong><span>Failed policy applies</span><router-link to="/policies">Review</router-link></div></div>
    </div>
  </section>
  <div class="enterprise-distribution">
    <section class="enterprise-data-card"><h2>Network segmentation distribution</h2><div class="enterprise-donut-row"><div class="enterprise-donut" :style="{'--portion':`${assignedPct}%`}"><span>{{assignedPct}}%</span></div><div class="enterprise-donut-legend"><div><strong>{{assignedPct}}%</strong> {{assigned}} assets with policies</div><div><strong>{{uncoveredPct}}%</strong> {{uncovered}} assets need a policy</div></div></div></section>
    <section class="enterprise-data-card"><h2>Asset distribution</h2><div class="enterprise-donut-row"><div class="enterprise-donut enterprise-donut-navy" :style="{'--portion':`${reachablePct}%`}"><span>{{reachablePct}}%</span></div><div class="enterprise-donut-legend"><div><strong>{{stats.reachableNodes}}</strong> reachable assets</div><div><strong>{{stats.totalNodes}}</strong> total assets</div></div></div></section>
    <section class="enterprise-data-card enterprise-data-summary"><h2>Operations</h2><div><i class="mdi mdi-account-group-outline"></i><span>Policies <strong>{{stats.policies}}</strong></span></div><div><i class="mdi mdi-lan-connect"></i><span>Agents online <strong>{{stats.agentsOnline}}</strong></span></div><div><i class="mdi mdi-alert-circle-outline"></i><span>Failed applies <strong>{{stats.failedApplies}}</strong></span></div></section>
  </div>
</template>
