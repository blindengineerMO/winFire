import fs from 'node:fs'
import os from 'node:os'
import express from 'express'
import {fileURLToPath} from 'node:url'
const root=fileURLToPath(new URL('..',import.meta.url))
process.env.DATA_DIR=fs.mkdtempSync(os.tmpdir()+'/winfire-views-ui-')
process.env.NODE_ENV='test';process.env.BOOTSTRAP_EMAIL='views-ui@example.test';process.env.BOOTSTRAP_PASSWORD='Views-fixture-only-123'
const {app}=await import('../api/src/app.js'),{bootstrap}=await import('../api/src/security.js'),{db,run}=await import('../api/src/db.js'),{closeDashboardTraffic}=await import('../api/src/services/dashboardTraffic.js')
await bootstrap()
run("INSERT INTO app_settings(key,value) VALUES('local_asset_cidrs','[\"10.0.0.0/8\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
const node=db.prepare('INSERT INTO nodes(id,hostname,ip,device_type) VALUES(?,?,?,?)'),pair=db.prepare("INSERT INTO network_map_pairs(map_key,source_node_id,destination_node_id,source_ip,destination_ip,protocol,destination_port,connection_count,first_seen_at,last_seen_at,updated_at) VALUES(?,?,?,?,?,'TCP',443,?,datetime('now'),datetime('now'),datetime('now'))")
for(let i=0;i<120;i++)node.run(`ui-node-${i}`,`Fixture node ${i}`,`10.42.0.${i+1}`,i===0?'switch':'auto')
for(let i=1;i<120;i++)pair.run(`ui-pair-${i}`,'ui-node-0',`ui-node-${i}`,'10.42.0.1',`10.42.0.${i+1}`,i)
run("INSERT INTO arp_entries(id,node_id,ip,mac,observed_at) VALUES('ui-arp','ui-node-0','10.42.0.2','aa:bb:cc:dd:ee:01',datetime('now'))")
run("INSERT INTO log_events(id,node_id,event_id,action,event_type,protocol,dst_port,event_time) VALUES('ui-event','ui-node-1',5157,'block','firewall','TCP',443,datetime('now'))")
app.use(express.static(root+'/web/dist'));app.get('/{*path}',(_req,res)=>res.sendFile(root+'/web/dist/index.html'))
const server=app.listen(Number(process.env.VIEWS_UI_PORT||3320),'127.0.0.1',()=>console.log('Views isolated UI fixture ready'))
process.on('SIGTERM',()=>server.close(async()=>{await closeDashboardTraffic();db.close();fs.rmSync(process.env.DATA_DIR,{recursive:true,force:true});process.exit(0)}))
