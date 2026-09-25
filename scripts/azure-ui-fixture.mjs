// Disposable local UI fixture. No Azure client or discovery scheduler is started.
import fs from 'node:fs'
import os from 'node:os'
import express from 'express'
import {fileURLToPath} from 'node:url'
const root=fileURLToPath(new URL('..',import.meta.url))
process.chdir(root)
process.env.DATA_DIR=fs.mkdtempSync(os.tmpdir()+'/winfire-azure-ui-')
process.env.NODE_ENV='test'
process.env.BOOTSTRAP_EMAIL='azure-ui@example.test'
process.env.BOOTSTRAP_PASSWORD='Azure-ui-fixture-only-123'
const {app}=await import('../api/src/app.js')
const {bootstrap}=await import('../api/src/security.js')
const {db,id,one}=await import('../api/src/db.js')
const {saveAzureCredential,saveConnection}=await import('../api/src/cloud/service.js')
const {saveScope,reconcileRecord}=await import('../api/src/cloud/inventory.js')
await bootstrap()
const owner=one('SELECT id FROM users WHERE email=?',process.env.BOOTSTRAP_EMAIL).id
const tenantId=id(),subscription=id(),scope=saveScope({name:'Azure UI fixture VNet',kind:'azure-vnet',cidrs:['10.42.0.0/24']},owner)
const credential=saveAzureCredential({name:'Azure UI fixture credential',tenantId,clientId:id(),authMethod:'secret',clientSecret:'Fixture-only-no-azure-access'},owner)
const connection=saveConnection({name:'Azure UI fixture connection',credentialId:credential.id,subscriptions:[subscription],scopeId:scope.id},owner)
for(let i=1;i<=32;i++){
 const record={provider:'azure',kind:'vm',tenantId,resourceId:`/subscriptions/${subscription}/resourceGroups/fixture/providers/Microsoft.Compute/virtualMachines/vm-${i}`,subscriptionId:subscription,resourceGroup:'fixture',name:`Fixture VM ${String(i).padStart(2,'0')}`,hostname:`vm-${i}`,uuid:id(),addresses:[`10.42.0.${i}`],networkIds:[],osName:i%2?'Windows':'Linux',osVersion:null,location:'Fixture region',providerStatus:'Succeeded',provenance:{osName:'Fixture Azure OS disk family'}}
 reconcileRecord(record,connection,'fixture-original',owner)
 if(i===1)reconcileRecord({...record,uuid:id()},connection,'fixture-recreated',owner)
}
app.use(express.static(root+'/web/dist'))
app.get('/{*path}',(_req,res)=>res.sendFile(root+'/web/dist/index.html'))
const server=app.listen(Number(process.env.AZURE_UI_PORT||3319),'127.0.0.1',()=>console.log('Azure disposable UI fixture ready'))
process.on('SIGTERM',()=>server.close(()=>{db.close();fs.rmSync(process.env.DATA_DIR,{recursive:true,force:true});process.exit(0)}))
