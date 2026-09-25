import {canonicalIp,unicastIp} from '../services/networkBoundary.js'
import {AzureError} from './client.js'
const versions={vm:'2024-07-01',nic:'2024-05-01',arc:'2025-01-13'}
const arrays=v=>Array.isArray(v)?v:[]
const lower=v=>String(v||'').toLowerCase()
const unique=values=>[...new Set(values.filter(Boolean))].sort()
const text=v=>typeof v==='string'?v.slice(0,2048):null
export function normalizeAzure(resource,{tenantId,nics=new Map()}={}){
  const p=resource.properties||{},arc=lower(resource.type)==='microsoft.hybridcompute/machines',interfaces=[]
  if(arc){
    for(const n of arrays(p.networkProfile?.networkInterfaces))interfaces.push({id:text(n.id),name:text(n.name),mac:text(n.macAddress),addresses:unique(arrays(n.ipAddresses).map(a=>canonicalIp(a.address)).filter(a=>unicastIp(a))),subnetId:null,publicIpId:null})
  }else{
    for(const ref of arrays(p.networkProfile?.networkInterfaces)){
      const n=nics.get(lower(ref.id)),np=n?.properties||{}
      for(const c of arrays(np.ipConfigurations))interfaces.push({id:text(ref.id),name:text(n?.name),mac:text(np.macAddress),addresses:unique([canonicalIp(c.properties?.privateIPAddress)].filter(a=>unicastIp(a))),subnetId:text(c.properties?.subnet?.id),publicIpId:text(c.properties?.publicIPAddress?.id)})
      if(!n)interfaces.push({id:text(ref.id),name:null,mac:null,addresses:[],subnetId:null,publicIpId:null,unavailable:true})
    }
  }
  const osName=text(arc?p.osName||p.osSku||p.osType:p.storageProfile?.osDisk?.osType),osVersion=arc?text(p.osVersion):null
  return {provider:arc?'azure-arc':'azure',tenantId,resourceId:resource.id,name:text(resource.name),kind:arc?'arc-machine':'vm',resourceType:resource.type,
    subscriptionId:resource.id?.split('/')[2]?.toLowerCase(),resourceGroup:resource.id?.split('/')[4],location:text(resource.location),tags:resource.tags||{},
    uuid:text(arc?p.vmUuid:p.vmId),hostname:text(p.osProfile?.computerName)||text(resource.name),fqdn:text(p.machineFqdn),osName,osVersion,
    hardware:{vmSize:text(p.hardwareProfile?.vmSize),manufacturer:text(p.detectedProperties?.manufacturer),model:text(p.detectedProperties?.model)},
    providerStatus:text(arc?p.status:p.provisioningState),powerState:text(p.instanceView?.statuses?.find(s=>s.code?.startsWith('PowerState/'))?.code),
    observedAt:arc&&Number.isFinite(Date.parse(p.lastStatusChange))?new Date(p.lastStatusChange).toISOString():null,
    interfaces,addresses:unique(interfaces.flatMap(i=>i.addresses)),macs:unique(interfaces.map(i=>i.mac)),networkIds:unique(interfaces.map(i=>i.subnetId?.split('/subnets/')[0])),
    provenance:{osName:arc?'Arc reported operating system':'Azure OS disk family',osVersion:arc?'Arc reported version':'Unavailable from VM configuration',addresses:arc?'Arc network profile':'Azure NIC configuration'},confidence:'provider-reported'}
}
export async function listAzure(client,path,{maxResources=100000}={}){
  const items=new Map(),pages=new Set(),initial=new URL(path,'https://management.azure.com');let next=path
  while(next){
    const url=new URL(next,'https://management.azure.com')
    if(url.origin!==initial.origin||url.pathname.toLowerCase()!==initial.pathname.toLowerCase()||pages.has(url.href))throw new AzureError('pagination_invalid','Azure pagination changed scope or repeated a page')
    pages.add(url.href);const page=await client.request(url.href)
    if(!Array.isArray(page.value))throw new AzureError('invalid_response','Azure list response has no resource collection')
    for(const item of page.value){if(typeof item.id!=='string'||!lower(item.id).startsWith(lower(initial.pathname.split('/providers/')[0])+'/'))throw new AzureError('invalid_resource','Azure returned an invalid resource identity');items.set(lower(item.id),item)}
    if(items.size>maxResources||pages.size>1000)throw new AzureError('resource_budget','Azure resource/page budget exhausted')
    next=page.nextLink||null
  }
  return [...items.values()]
}
export async function scopeReadPermission(client,base){
  const permissions=[],seen=new Set();let next=`${base}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01`
  const path=new URL(next,'https://management.azure.com').pathname
  while(next){
    const url=new URL(next,'https://management.azure.com')
    if(url.origin!=='https://management.azure.com'||url.pathname.toLowerCase()!==path.toLowerCase()||seen.has(url.href)||seen.size>=100)throw new AzureError('permission_incomplete','Could not verify complete permission scope')
    seen.add(url.href);const page=await client.request(url.href)
    if(!Array.isArray(page.value))throw new AzureError('permission_incomplete','Azure did not return scope permissions')
    permissions.push(...page.value);next=page.nextLink||null
  }
  const match=(pattern,value)=>new RegExp('^'+String(pattern).replace(/[.+?^${}()|[\]\\]/g,'\\$&').replaceAll('*','.*')+'$','i').test(value)
  const required=['Microsoft.Compute/virtualMachines/read','Microsoft.HybridCompute/machines/read','Microsoft.Network/networkInterfaces/read']
  if(!required.every(action=>permissions.some(p=>arrays(p.actions).some(v=>match(v,action))&&!arrays(p.notActions).some(v=>match(v,action)))))throw new AzureError('permission_denied','Reader or equivalent VM, Arc and NIC reads must cover the entire selected scope')
  return true
}
export async function discoverAzure(config,settings,client,{onProgress=()=>{},preflight=false}={}){
  const records=new Map(),scopes=[]
  for(const subscription of config.subscriptions){
    for(const group of config.resourceGroups.length?config.resourceGroups:[null]){
      const base=`/subscriptions/${subscription}${group?'/resourceGroups/'+encodeURIComponent(group):''}`,scope={subscriptionId:subscription,resourceGroup:group,complete:true,errors:[],counts:{}}
      scopes.push(scope);let machines=[],arc=[],nicRows=[]
      try{await scopeReadPermission(client,base)}catch(error){if(error.code==='cancelled')throw error;scope.complete=false;scope.errors.push({kind:'scope',code:error.code||'permission_incomplete',message:error instanceof AzureError?error.message:'Scope permissions could not be verified'})}
      for(const [kind,type,version] of [['vm','Microsoft.Compute/virtualMachines',versions.vm],['arc','Microsoft.HybridCompute/machines',versions.arc],['nic','Microsoft.Network/networkInterfaces',versions.nic]]){
        try{
          const rows=await listAzure(client,`${base}/providers/${type}?api-version=${version}`)
          scope.counts[kind]=rows.length
          if(kind==='vm')machines=rows;else if(kind==='arc')arc=rows;else nicRows=rows
        }catch(error){if(['cancelled','request_budget','authentication_failed','identity_unavailable'].includes(error.code))throw error;scope.complete=false;scope.errors.push({kind,code:error.code||'discovery_error',message:error instanceof AzureError?error.message:'Azure discovery could not complete this scope'})}
        await onProgress({scopes,records:records.size,requests:client.requests})
      }
      if(preflight)continue
      const nics=new Map(nicRows.map(n=>[lower(n.id),n]))
      // NICs may live in another selected/unselected resource group. Read only referenced NICs in selected subscriptions.
      for(const vm of machines){for(const ref of arrays(vm.properties?.networkProfile?.networkInterfaces)){
        if(nics.has(lower(ref.id)))continue
        if(!/^\/subscriptions\/[^/]+\/resourceGroups\/[^/]+\/providers\/Microsoft.Network\/networkInterfaces\/[^/]+$/i.test(ref.id||'')||!config.subscriptions.includes(lower(ref.id.split('/')[2]))){scope.complete=false;continue}
        try{nics.set(lower(ref.id),await client.request(`${ref.id}?api-version=${versions.nic}`))}
        catch(error){if(error.code==='cancelled')throw error;scope.complete=false;scope.errors.push({kind:'nic',code:error.code||'nic_unavailable',message:'A VM network interface could not be read'})}
      }}
      for(const resource of [...machines,...arc]){
        if(!Object.entries(config.tags).every(([k,v])=>resource.tags?.[k]===v))continue
        const record=normalizeAzure(resource,{tenantId:settings.tenantId,nics});records.set(lower(resource.id),record)
      }
      await onProgress({scopes,records:records.size,requests:client.requests})
    }
  }
  return {records:[...records.values()],scopes,complete:scopes.every(s=>s.complete),requests:client.requests,readOnly:true}
}
