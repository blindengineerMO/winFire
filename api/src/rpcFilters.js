import {isIP} from 'node:net'
import crypto from 'node:crypto'
import {validateAddressExpression} from '@winfire/shared'

const uuid=/^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$/i
const scalar=value=>String(value??'').trim()

function ipv4ToInteger(value){return value.split('.').reduce((result,part)=>(result<<8)|Number(part),0)>>>0}
function integerToIpv4(value){return [24,16,8,0].map(shift=>(value>>>shift)&255).join('.')}

function sourceCondition(source){
  const value=scalar(source)
  if(!value||value.toLowerCase()==='any')return null
  if(!validateAddressExpression(value)||value.includes(','))throw Object.assign(new Error('RPC source must be one IP address or CIDR'),{status:400})
  const [address,prefixText]=value.split('/')
  const family=isIP(address)
  if(family===4){
    const prefix=prefixText===undefined?32:Number(prefixText)
    const mask=prefix===0?0:(0xffffffff<<(32-prefix))>>>0
    const start=ipv4ToInteger(address)&mask
    const end=(start|(~mask>>>0))>>>0
    return {field:'remote_addr_v4',matchType:prefix===32?'equal':'range',data:prefix===32?address:`${integerToIpv4(start)}-${integerToIpv4(end)}`}
  }
  if(family!==6)throw Object.assign(new Error('RPC source must be an IPv4 or IPv6 address/CIDR'),{status:400})
  // Keep IPv6 exact until Windows' netsh range encoding is verified on a
  // supported target. Exact IPv6 conditions are fully supported by netsh.
  if(prefixText!==undefined&&Number(prefixText)!==128)throw Object.assign(new Error('RPC IPv6 sources must currently be an exact address'),{status:400})
  return {field:'remote_addr_v6',matchType:'equal',data:address}
}

export function normalizeRpcFilter(input,{idValue=null}={}){
  const interfaceUuid=scalar(input.interfaceUuid??input.interface_uuid)
  if(!uuid.test(interfaceUuid))throw Object.assign(new Error('RPC interface UUID is invalid'),{status:400})
  const opnum=input.opnum===undefined||input.opnum===null||input.opnum===''?null:Number(input.opnum)
  if(opnum!==null&&(!Number.isInteger(opnum)||opnum<0||opnum>65535))throw Object.assign(new Error('RPC opnum must be an integer from 0 to 65535'),{status:400})
  const action=scalar(input.action).toLowerCase()
  if(!['allow','block','continue'].includes(action))throw Object.assign(new Error('RPC action must be allow, block, or continue'),{status:400})
  const id=scalar(idValue||input.id||input.filterKey)
  if(id&&!uuid.test(id))throw Object.assign(new Error('RPC filter key is invalid'),{status:400})
  const filterKey=id||crypto.randomUUID()
  const audit=input.audit===undefined?true:!!input.audit
  const source=scalar(input.source)
  const conditions=[{field:'if_uuid',matchType:'equal',data:interfaceUuid.replace(/[{}]/g,'')}]
  if(opnum!==null)conditions.push({field:'opnum',matchType:'equal',data:String(opnum)})
  const sourceRule=sourceCondition(source)
  if(sourceRule)conditions.push(sourceRule)
  const canonicalSource=source.toLowerCase()==='any'||!source?null:source
  return {id:filterKey,filterKey,interfaceUuid:interfaceUuid.replace(/[{}]/g,''),opnum,source:canonicalSource,action,audit:action==='allow'?audit:false,label:scalar(input.label).slice(0,160),layer:'um',conditions}
}

export function publicRpcFilter(row){
  if(!row)return null
  const normalized=normalizeRpcFilter({id:row.id,interfaceUuid:row.interface_uuid,opnum:row.opnum,source:row.source,action:row.action,audit:!!row.audit,label:row.label},{idValue:row.id})
  return {...row,...normalized,audit:!!row.audit,appliedAt:row.applied_at||null}
}
