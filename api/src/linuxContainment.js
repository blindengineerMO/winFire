import fs from 'node:fs'
import {z} from 'zod'
import {sshExec} from './sshConnector.js'
import {normalizeCidrs} from './services/networkBoundary.js'
const script=fs.readFileSync(new URL('../sidecar/linux_containment.py',import.meta.url),'utf8')
export function linuxContainmentCommand(operation,input){
 const id=z.string().uuid().parse(input.id);if(!['containment_start','containment_restore'].includes(operation))throw Error('Unsupported containment operation')
 const data={id,operation};if(operation==='containment_start'){data.seconds=z.number().int().min(120).max(3600).parse(input.seconds);data.protectedCidrs=normalizeCidrs(input.protectedCidrs)}
 const bootstrap="import base64;exec(base64.b64decode('"+Buffer.from(script).toString('base64')+"'))"
 return `sudo -n python3 -c "${bootstrap}" '${Buffer.from(JSON.stringify(data)).toString('base64')}'`
}
export async function linuxContainment(connection,operation,args){const r=await sshExec({...connection,command:linuxContainmentCommand(operation,args),timeout:60000});if(r.code!==0)throw Error('Linux containment: '+String(r.stderr||'operation failed').slice(0,1000));return JSON.parse(r.stdout)}
