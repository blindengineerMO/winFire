<script setup>
import {ref} from 'vue'
const copied=ref(false)
async function copy(){
  try{await navigator.clipboard.writeText(`${location.origin}/tools`);copied.value=true;setTimeout(()=>copied.value=false,1800)}catch{}
}
</script>

<template>
  <main class="tools-page">
    <section class="tools-card glass">
      <div class="tools-brand"><img src="/winfire-mark.png" alt=""><span><strong>WINFIRE</strong><small>SECURE</small></span></div>
      <span class="eyebrow">CONTROL PLANE TOOLS</span>
      <h1>Internet visibility for managed browsers</h1>
      <p class="tools-lead">Install the WinFIRE browser extension, enroll it with a short-lived administrator code, report privacy-preserving navigation metadata, and receive published Internet allow or block rules.</p>
      <div class="tools-actions"><a class="button primary" href="/tools/winfire-internet-chromium.zip" download><i class="mdi mdi-download"></i> Download Chrome / Edge package</a><a class="button secondary" href="/tools/winfire-internet-firefox.zip" download><i class="mdi mdi-firefox"></i> Download Firefox package</a><a class="button secondary" href="/login">Operator sign in</a><button class="button secondary" @click="copy">{{copied?'Link copied':'Copy tools link'}}</button></div>
      <div class="tools-grid"><article><i class="mdi mdi-eye-outline"></i><h2>Host and path metadata</h2><p>Query strings, fragments, page contents, forms, cookies, credentials, and private browsing are excluded.</p></article><article><i class="mdi mdi-shield-key-outline"></i><h2>Administrator enrollment</h2><p>Create a one-time code in Administration, then approve the browser permissions in its options page.</p></article><article><i class="mdi mdi-chart-timeline-variant"></i><h2>Visibility and policy</h2><p>Search Internet activity separately from Firewall Events, then stage, publish, and roll back browser rules from the Internet policy studio.</p></article></div>
      <details class="tools-install"><summary>Installation and privacy</summary><ol><li>Download and unzip the package.</li><li>Open <strong>chrome://extensions</strong> or <strong>edge://extensions</strong>, enable Developer mode, and choose Load unpacked.</li><li>Open the extension options page, paste the one-time code from WinFIRE, and approve host access.</li><li>Review the included <a href="/tools/winfire-internet-chromium/PRIVACY.md">privacy notice</a> before enrolling.</li></ol><p>Production deployments should publish the signed package through the Chrome Web Store or Edge Add-ons. Direct packages are intended for development and controlled enterprise distribution.</p></details>
    </section>
  </main>
</template>

<style scoped>
.tools-page{min-height:100vh;display:grid;place-items:center;padding:28px;background:radial-gradient(ellipse at 75% 5%,#14305288,transparent 42%),#07111d;color:#eaf3f9}.tools-card{width:min(980px,100%);padding:clamp(25px,5vw,58px);border-radius:16px}.tools-brand{display:flex;align-items:center;gap:10px;margin-bottom:44px}.tools-brand img{width:38px;height:38px}.tools-brand strong{display:block;font-size:1.1rem;letter-spacing:.08em}.tools-brand small{display:block;color:#8ea4b5;font:500 .58rem 'JetBrains Mono',monospace;letter-spacing:.08em;margin-top:2px}.tools-card h1{max-width:700px;font-size:clamp(2rem,5vw,4rem);line-height:1.05}.tools-lead{max-width:680px;font-size:.95rem}.tools-actions{display:flex;gap:9px;flex-wrap:wrap;margin:26px 0 35px}.tools-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.tools-grid article{padding:17px;border:1px solid var(--border);border-radius:9px;background:#0d2131aa}.tools-grid .mdi{font-size:1.5rem;color:var(--green)}.tools-grid h2{margin:12px 0 7px}.tools-grid p,.tools-install{font-size:.75rem}.tools-install{margin-top:28px;border-top:1px solid var(--border);padding-top:18px}.tools-install summary{cursor:pointer;color:var(--green);font-weight:700}.tools-install li{margin:.55rem 0}.tools-install a{color:var(--green)}@media(max-width:700px){.tools-grid{grid-template-columns:1fr}.tools-card{padding:25px}.tools-brand{margin-bottom:28px}}
</style>
