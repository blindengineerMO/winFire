import dgram from 'node:dgram'
import tls from 'node:tls'
import fs from 'node:fs'
import {all,run} from '../db.js'
import {canonicalIp} from '../services/networkBoundary.js'
import {ingestDatagram,importSyslog,recordRejected} from './service.js'
import {randomUUID} from 'node:crypto'
export const receiverStatus={queued:0,dropped:0,listeners:0}
// Receivers are opt-in. The authenticated import API is available without opening listener ports.
export function startTelemetryReceivers(env=process.env){
 const handles=[],queue=[];let draining=false,dropped=0
 const enqueue=job=>{if(queue.length>=256){dropped++;receiverStatus.dropped=dropped;return false}queue.push(job);receiverStatus.queued=queue.length;if(!draining){draining=true;setImmediate(drain)}return true}
 const drain=()=>{for(let n=0;n<16&&queue.length;n++){const job=queue.shift();receiverStatus.queued=queue.length;try{job.run()}catch{/* Per-exporter failures are recorded by ingestion. */}}if(queue.length)setImmediate(drain);else draining=false}
 if(env.TELEMETRY_UDP_PORT){
  const port=Number(env.TELEMETRY_UDP_PORT);if(!Number.isInteger(port)||port<1024||port>65535)throw new Error('TELEMETRY_UDP_PORT must be 1024–65535')
  const socket=dgram.createSocket(env.TELEMETRY_UDP_IPV6==='true'?'udp6':'udp4');socket.on('error',e=>console.error('Flow receiver:',e.message));socket.on('message',(packet,remote)=>{
   if(packet.length<2)return;const format=({9:'netflow-v9',10:'ipfix-v10'})[packet.readUInt16BE(0)];if(!format)return
   const e=all('SELECT id FROM telemetry_exporters WHERE enabled=1 AND source_ip=? AND format=?',canonicalIp(remote.address),format)[0];if(!e)return
   enqueue({exporterId:e.id,run:()=>ingestDatagram(e.id,packet)})
  });socket.bind(port,env.TELEMETRY_BIND||'127.0.0.1');handles.push(socket)
 }
 if(env.TELEMETRY_SYSLOG_TLS_PORT){
  const port=Number(env.TELEMETRY_SYSLOG_TLS_PORT);if(!Number.isInteger(port)||port<1024||port>65535)throw new Error('TELEMETRY_SYSLOG_TLS_PORT must be 1024–65535')
  const server=tls.createServer({key:fs.readFileSync(env.TELEMETRY_TLS_KEY),cert:fs.readFileSync(env.TELEMETRY_TLS_CERT),ca:fs.readFileSync(env.TELEMETRY_TLS_CA),requestCert:true,rejectUnauthorized:true,minVersion:'TLSv1.2'},socket=>{
   const fingerprint=socket.getPeerCertificate().fingerprint256?.replaceAll(':','').toLowerCase(),source=canonicalIp(socket.remoteAddress)
   const matches=all("SELECT * FROM telemetry_exporters WHERE enabled=1 AND source_ip=? AND tls_fingerprint=? AND format IN ('pf-filterlog','mikrotik-firewall','sonicwall-kv')",source,fingerprint||'')
   if(matches.length!==1){socket.destroy();return}const e=matches[0],session=randomUUID();let buffer=Buffer.alloc(0),sequence=0
   socket.setTimeout(60000,()=>socket.destroy());socket.on('error',()=>{});socket.on('data',chunk=>{
    buffer=Buffer.concat([buffer,chunk]);if(buffer.length>65536){recordRejected(e.id,new Error('TLS syslog frame buffer limit exceeded'));socket.destroy();return}
    while(buffer.length){
     let payload,end;const space=buffer.indexOf(32),prefix=space>0&&space<=6?buffer.subarray(0,space).toString():''
     if(/^\d+$/.test(prefix)){const length=Number(prefix);if(length<1||length>16384){socket.destroy();return}end=space+1+length;if(buffer.length<end)break;payload=buffer.subarray(space+1,end)}else{end=buffer.indexOf(10);if(end<0)break;payload=buffer.subarray(0,end);end++}
     buffer=buffer.subarray(end);const line=payload.toString('utf8').replace(/\r$/,''),captureKey=`tls:${session}:${sequence++}`
     if(!enqueue({exporterId:e.id,run:()=>importSyslog(e.id,{captureKey,lines:[line]},null)})){socket.destroy();return}
    }
   })
  });server.maxConnections=64;server.on('error',e=>console.error('TLS syslog receiver:',e.message));server.listen(port,env.TELEMETRY_BIND||'127.0.0.1');handles.push(server)
 }
 receiverStatus.listeners=handles.length
 return {close:()=>handles.forEach(h=>h.close()),metrics:()=>({queued:queue.length,dropped,listeners:handles.length})}
}
