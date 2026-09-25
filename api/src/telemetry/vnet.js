import {createHash} from 'node:crypto'
import {z} from 'zod'
import {db,run,one,all,now,json,audit} from '../db.js'
import {openSealed} from '../security.js'
import {listAzure} from '../cloud/azureAdapter.js'
import {azureClient} from '../cloud/client.js'
import {getExporter,saveObservations} from './service.js'
const hash=v=>createHash('sha256').update(v).digest('hex'),fail=(message,status=400)=>{throw Object.assign(new Error(message),{status})}
export function decodeVnet(document){
 if(!Array.isArray(document?.records)||document.records.length>10000)fail('Expected VNet flow-log records')
 const rows=[]
 for(const record of document.records){
  if(record.flowLogVersion!==4||record.category!=='FlowLogFlowEvent'||!record.flowLogGUID||!record.targetResourceID)fail('Only Azure VNet flow-log version 4 is supported; legacy NSG logs use a different schema')
  for(const flow of record.flowRecords?.flows||[])for(const group of flow.flowGroups||[])for(const tuple of group.flowTuples||[]){
   if(typeof tuple!=='string')fail('Invalid VNet flow tuple');const f=tuple.split(',');if(f.length!==13||!['I','O'].includes(f[6])||!['B','C','E','D'].includes(f[7]))fail('Unsupported VNet tuple format')
   const timestamp=Number(f[0]);if(!Number.isFinite(timestamp)||timestamp<=0)fail('Invalid VNet tuple timestamp')
   const eventTime=new Date(timestamp<1e12?timestamp*1000:timestamp).toISOString()
   rows.push({captureKey:hash(json([record.flowLogGUID,record.macAddress,record.targetResourceID,flow.aclID,group.rule,tuple])),srcIp:f[1],dstIp:f[2],srcPort:Number(f[3]),dstPort:Number(f[4]),protocol:({6:'TCP',17:'UDP',1:'ICMP',58:'ICMPv6'})[f[5]]||f[5],direction:null,action:f[7]==='D'?'block':null,eventTime,metadata:{format:'azure-vnet-v4',flowLogGuid:record.flowLogGUID,flowLogResourceId:record.flowLogResourceID,targetResourceId:record.targetResourceID,macAddress:record.macAddress,aclId:flow.aclID,rule:group.rule,originalDirection:f[6],state:f[7],encryption:f[8],packetsSent:f[9]||null,bytesSent:f[10]||null,packetsReceived:f[11]||null,bytesReceived:f[12]||null,pathEvidence:'observed-cloud',reachability:'indeterminate',observationCountNotConnections:true}})
   if(rows.length>10000)fail('Blob exceeds 10,000 tuples; import smaller captures',413)
  }
 }
 return rows
}
export const blobSchema=z.object({credentialId:z.string().min(1),account:z.string().regex(/^[a-z0-9]{3,24}$/),container:z.string().regex(/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/),blob:z.string().min(1).max(2048).refine(v=>!v.split('/').some(s=>s==='.'||s==='..'))}).strict()
async function boundedBody(response){let length=0;const chunks=[];const reader=response.body?.getReader();if(!reader)fail('Azure Storage returned no content',502);try{while(true){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>16*1024*1024)fail('Blob exceeds the 16 MiB import limit',413);chunks.push(Buffer.from(value))}}finally{await reader.cancel().catch(()=>{})}try{return JSON.parse(Buffer.concat(chunks).toString())}catch{fail('Blob contains invalid JSON',400)}}
export async function importVnetBlob(exporterId,input,actor,{fetchImpl=fetch}={}){
 const q=blobSchema.parse(input),e=getExporter(exporterId);if(e.format!=='azure-vnet')fail('Choose an Azure VNet exporter')
 const credential=one("SELECT * FROM credentials WHERE id=? AND type='azure'",q.credentialId);if(!credential)fail('Choose an Azure credential from the vault')
 const url=`https://${q.account}.blob.core.windows.net/${q.container}/${q.blob.split('/').map(encodeURIComponent).join('/')}`,previous=one('SELECT * FROM vnet_blob_checkpoints WHERE exporter_id=? AND blob_url=?',e.id,url)
 const token=await azureClient(openSealed(credential.encrypted_blob),{fetchImpl,tokenScope:'https://storage.azure.com/.default'}).accessToken()
 const response=await fetchImpl(url,{method:'GET',redirect:'error',headers:{Authorization:`Bearer ${token}`,'x-ms-version':'2023-11-03',...(previous?.etag?{'If-None-Match':previous.etag}:{})},signal:AbortSignal.timeout(30000)})
 if(response.status===304){run('UPDATE vnet_blob_checkpoints SET checked_at=? WHERE exporter_id=? AND blob_url=?',now(),e.id,url);return {accepted:0,unchanged:true}}
 if(!response.ok){await response.body?.cancel();fail(response.status===403?'Azure Storage access denied. Grant Storage Blob Data Reader on this selected container; ARM Reader does not grant blob access.':`Azure Storage read failed (HTTP ${response.status}); check the selected account, container and blob`,502)}
 const rows=decodeVnet(await boundedBody(response)),etag=response.headers.get('etag')
 return db.transaction(()=>{const result=saveObservations(e,rows,url);run('INSERT INTO vnet_blob_checkpoints(exporter_id,blob_url,etag,checked_at,observations) VALUES(?,?,?,?,?) ON CONFLICT(exporter_id,blob_url) DO UPDATE SET etag=excluded.etag,checked_at=excluded.checked_at,observations=excluded.observations',e.id,url,etag,now(),rows.length);audit(actor,'telemetry.vnet.import','telemetry-exporter',e.id,null,{url,etag,...result});return result})()
}
export async function refreshCloudNetwork(connectionId,actor,{clientFactory=azureClient}={}){
 const c=one('SELECT * FROM azure_connections WHERE id=?',connectionId);if(!c)fail('Azure connection not found',404)
 const config=JSON.parse(c.config_json),credential=one("SELECT * FROM credentials WHERE id=? AND type='azure'",c.credential_id);if(!credential)fail('Azure vault credential is unavailable',409)
 const client=clientFactory(openSealed(credential.encrypted_blob)),rows=[]
 for(const subscription of config.subscriptions)for(const kind of ['virtualNetworks','networkInterfaces','networkSecurityGroups','routeTables']){
  const resources=await listAzure(client,`/subscriptions/${subscription}/providers/Microsoft.Network/${kind}?api-version=2024-05-01`,{maxResources:10000})
  for(const resource of resources){const group=String(resource.id||'').split('/')[4];if(config.resourceGroups?.length&&!config.resourceGroups.some(g=>g.toLowerCase()===group?.toLowerCase()))continue;rows.push({resource,kind});if(rows.length>10000)fail('Network context exceeds 10,000 resources',413)}
 }
 db.transaction(()=>{for(const {resource,kind} of rows)run('INSERT INTO cloud_network_context(connection_id,resource_id,kind,snapshot_json,observed_at) VALUES(?,?,?,?,?) ON CONFLICT(connection_id,resource_id) DO UPDATE SET snapshot_json=excluded.snapshot_json,observed_at=excluded.observed_at',c.id,resource.id.toLowerCase(),kind,json(resource),now());audit(actor,'azure.network-context.refresh','azure-connection',c.id,null,{resources:rows.length})})();return {resources:rows.length,evidence:'configured',reachability:'indeterminate',reason:'Configuration does not establish an actively verified path; service tags and NAT are not evaluated'}
}
export function cloudNetworkContext(input={}){const q=z.object({connectionId:z.string().optional(),kind:z.string().optional(),page:z.coerce.number().int().min(1).default(1),pageSize:z.coerce.number().int().min(1).max(250).default(25)}).parse(input),where=[],args=[];for(const [field,column] of [['connectionId','connection_id'],['kind','kind']])if(q[field]){where.push(column+'=?');args.push(q[field])}const suffix=where.length?' WHERE '+where.join(' AND '):'';return {items:all('SELECT * FROM cloud_network_context'+suffix+' ORDER BY resource_id LIMIT ? OFFSET ?',...args,q.pageSize,(q.page-1)*q.pageSize).map(r=>({...r,snapshot:JSON.parse(r.snapshot_json),snapshot_json:undefined,evidence:'configured',reachability:'indeterminate'})),total:one('SELECT count(*) n FROM cloud_network_context'+suffix,...args).n,page:q.page,pageSize:q.pageSize}}
