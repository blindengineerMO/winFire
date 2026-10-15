import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import supertest from 'supertest'
import {searchLogEvents} from '../src/logSearch.js'

const dir=fs.mkdtempSync(path.join(os.tmpdir(),'winfire-log-search-'))
process.env.DATA_DIR=dir
process.env.BOOTSTRAP_EMAIL='owner@log-search.test'
process.env.BOOTSTRAP_PASSWORD='log-search-test-password'
const {app}=await import('../src/app.js')
const {bootstrap}=await import('../src/security.js')
const {db}=await import('../src/db.js')
await bootstrap()
const login=await supertest(app).post('/api/v1/auth/login').send({email:process.env.BOOTSTRAP_EMAIL,password:process.env.BOOTSTRAP_PASSWORD}).expect(200)
const request=query=>supertest(app).get('/api/v1/logs/search').query(query).set('Authorization',`Bearer ${login.body.accessToken}`)
test.after(()=>{db.close();fs.rmSync(dir,{recursive:true,force:true})})
db.prepare("INSERT INTO nodes(id,hostname,ip) VALUES('cursor-node','Cursor node','192.0.2.1')").run()
db.prepare("INSERT INTO event_patterns(id,fingerprint,protocol,src_ip,dst_ip,dst_port,direction,program,event_type) VALUES('pattern','pattern','TCP','192.0.2.1','198.51.100.1',443,'out','client.exe','firewall')").run()
const insert=db.prepare('INSERT INTO log_events(id,node_id,event_id,action,event_time,received_at,pattern_id,event_type,protocol,dst_port,direction,program) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
db.transaction(()=>{
  for(let i=0;i<63;i++){
    const at=new Date(Date.UTC(2026,8,19,12,0,0,Math.floor(i/3))).toISOString()
    insert.run(`cursor-${String(i).padStart(3,'0')}`,'cursor-node',5156,i%2?'block':'allow',i%5===0?null:at,at,i%2?'pattern':null,i%2?null:'firewall',i%2?null:'TCP',i%2?null:443,i%2?null:'out',i%2?null:'client.exe')
  }
})()
const base={nodeId:'cursor-node',pagination:'cursor',includeTotal:'false',pageSize:10}

test('cursor pages traverse timestamp ties, compacted events and received-time fallbacks in both directions',async()=>{
  for(const sortDir of ['asc','desc']){
    const expected=db.prepare(`SELECT id FROM log_events WHERE node_id=? ORDER BY COALESCE(julianday(COALESCE(event_time,received_at)),0) ${sortDir},id ${sortDir}`).all(base.nodeId).map(row=>row.id)
    const actual=[];let cursor
    do{
      const {body}=await request({...base,sortDir,...(cursor?{cursor}:{})}).expect(200)
      assert.equal(body.total,null);assert.equal(body.totalPages,null)
      assert.ok(body.items.length<=10)
      assert.ok(body.items.every(row=>row.protocol==='TCP'&&row.dst_port===443&&row.traffic_service==='HTTPS web traffic'))
      actual.push(...body.items.map(row=>row.id));cursor=body.nextCursor
      assert.equal(body.hasMore,!!cursor)
    }while(cursor)
    assert.deepEqual(actual,expected)
  }
})

test('continuation does not repeat rows after newer inserts or depend on the anchor still existing',async()=>{
  const first=(await request(base).expect(200)).body
  const anchor=first.items.at(-1)
  insert.run('new-arrival','cursor-node',5156,'allow','2026-09-20T00:00:00Z','2026-09-20T00:00:00Z','pattern',null,null,null,null,null)
  db.prepare('DELETE FROM log_events WHERE id=?').run(anchor.id)
  const second=(await request({...base,cursor:first.nextCursor}).expect(200)).body
  assert.ok(second.items.every(row=>!first.items.some(item=>item.id===row.id)&&row.id!=='new-arrival'))
  db.prepare('DELETE FROM log_events WHERE id=?').run('new-arrival')
})

test('cursor validation rejects malformed tokens, changed scopes and unsupported sorts',async()=>{
  const first=(await request(base).expect(200)).body
  for(const query of [
    {...base,cursor:'invalid'},
    {...base,cursor:first.nextCursor,action:'block'},
    {...base,cursor:first.nextCursor,sortDir:'asc'},
    {...base,cursor:first.nextCursor,pageSize:25},
    {...base,sortBy:'program'},
    {cursor:first.nextCursor},
  ])await request(query).expect(400)
})

test('fractional and offset timestamps filter chronologically using the indexed expression',async()=>{
  const result=(await request({...base,from:'2026-09-19T07:00:00.006-05:00',to:'2026-09-19T12:00:00.008Z'}).expect(200)).body
  assert.equal(result.items.length,9)
  assert.equal(result.hasMore,false)
})

test('empty and exact-size final chunks do not claim another page',async()=>{
  const empty=(await request({...base,eventId:9999}).expect(200)).body
  assert.deepEqual(empty.items,[]);assert.equal(empty.hasMore,false);assert.equal(empty.nextCursor,null)
  const exact=(await request({...base,pageSize:62}).expect(200)).body
  assert.equal(exact.items.length,62);assert.equal(exact.hasMore,false);assert.equal(exact.nextCursor,null)
})

test('count-free queries use time indexes and enrich only the selected page',()=>{
  const statements=[],plans=[]
  const connection={prepare(sql){
    statements.push(sql)
    return {all(...args){plans.push(...db.prepare('EXPLAIN QUERY PLAN '+sql).all(...args).map(row=>row.detail));return db.prepare(sql).all(...args)},get(...args){return db.prepare(sql).get(...args)}}
  }}
  const first=searchLogEvents(connection,base)
  searchLogEvents(connection,{...base,cursor:first.nextCursor})
  assert.ok(statements.every(sql=>!sql.includes('COUNT(*)')))
  assert.ok(plans.some(detail=>detail.includes('idx_logs_search_node_time')))
  assert.ok(plans.some(detail=>detail.includes('SEARCH e USING INDEX idx_logs_search_node_time')&&detail.includes('<expr>')))
  assert.ok(statements.every(sql=>sql.includes('AS MATERIALIZED')))
})

test('legacy offset clients retain exact totals, filters and alternate sorting',async()=>{
  const result=(await request({nodeId:base.nodeId,page:2,pageSize:10,sortBy:'program'}).expect(200)).body
  assert.equal(result.total,62);assert.equal(result.totalPages,7);assert.equal(result.items.length,10)
  const withoutCount=(await request({nodeId:base.nodeId,page:2,pageSize:10,sortBy:'program',includeTotal:'false'}).expect(200)).body
  assert.deepEqual(withoutCount.items,result.items);assert.equal(withoutCount.total,null)
})
