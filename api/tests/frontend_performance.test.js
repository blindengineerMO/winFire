import test from 'node:test'
import assert from 'node:assert/strict'
import {createMappingLoader} from '../../web/src/services/mappingLoader.js'

const storage=new Map()
globalThis.localStorage={getItem:key=>storage.get(key)??null,setItem:(key,value)=>storage.set(key,value),removeItem:key=>storage.delete(key)}
let redirects=[]
globalThis.location={assign:url=>redirects.push(url)}
const {api,session}=await import('../../web/src/services/api.js')
const originalFetch=globalThis.fetch
const tokens={accessToken:'old-access',refreshToken:'old-refresh',user:{id:'operator'}}
const rotated={...tokens,accessToken:'new-access',refreshToken:'new-refresh'}
const response=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}})
test.beforeEach(()=>{session.clear();session.setTokens(tokens);redirects=[]})
test.afterEach(()=>{globalThis.fetch=originalFetch})

test('parallel dashboard requests rotate a refresh credential only once',async()=>{
  let refreshes=0,release
  const gate=new Promise(resolve=>{release=resolve})
  globalThis.fetch=async(url,options)=>{
    if(url.endsWith('/auth/refresh')){refreshes++;await gate;return response(rotated)}
    return options.headers.Authorization==='Bearer old-access'?response({error:'Expired'},401):response({ok:true})
  }
  const pending=Promise.all(['/summary','/traffic','/events'].map(path=>api(path)))
  await new Promise(resolve=>setImmediate(resolve))
  release()
  assert.ok((await pending).every(value=>value.ok))
  assert.equal(refreshes,1)
  assert.equal(session.refresh,'new-refresh')
  assert.deepEqual(redirects,[])
})

test('a late unauthorized response reuses an already refreshed access token',async()=>{
  let refreshes=0,release
  const gate=new Promise(resolve=>{release=resolve})
  globalThis.fetch=async(url,options)=>{
    if(url.endsWith('/auth/refresh')){refreshes++;return response(rotated)}
    if(options.headers.Authorization==='Bearer new-access')return response({ok:true})
    if(url.endsWith('/slow'))await gate
    return response({error:'Expired'},401)
  }
  const slow=api('/slow')
  await api('/fast')
  release()
  assert.equal((await slow).ok,true)
  assert.equal(refreshes,1)
})

test('a completed refresh cannot resurrect a signed-out session',async()=>{
  let release
  const gate=new Promise(resolve=>{release=resolve})
  globalThis.fetch=async url=>{
    if(url.endsWith('/auth/refresh')){await gate;return response(rotated)}
    return response({error:'Expired'},401)
  }
  const pending=api('/summary')
  await new Promise(resolve=>setImmediate(resolve))
  session.clear();release()
  await assert.rejects(pending,/refresh session/)
  assert.equal(session.token,null)
  assert.equal(session.refresh,null)
})

test('temporary refresh failures preserve the session and aborted reads do not refresh',async()=>{
  let refreshes=0
  globalThis.fetch=async url=>url.endsWith('/auth/refresh')?(refreshes++,response({error:'Unavailable'},503)):response({error:'Expired'},401)
  await assert.rejects(api('/summary'),/refresh session/)
  assert.equal(session.refresh,'old-refresh')
  assert.deepEqual(redirects,[])
  const controller=new AbortController();controller.abort()
  await assert.rejects(api('/summary',{signal:controller.signal}),{name:'AbortError'})
  assert.equal(refreshes,1)
})

test('mapping loads the visible tab only and pagination excludes talker aggregation',async()=>{
  const calls=[],commits=[]
  const service=Object.fromEntries(['listPairs','listTalkers','listTopology','listArp'].map(name=>[name,async filters=>{calls.push({name,filters});return {items:[],rows:[]}}]))
  const loader=createMappingLoader(service,{commit:(...value)=>commits.push(value),setLoading:()=>{},onError:error=>{throw error}})
  await loader.load('topology',{})
  await loader.load('topology',{})
  assert.deepEqual(calls.map(x=>x.name),['listTopology'])
  await loader.load('pairs',{}, {page:1})
  await loader.load('pairs',{}, {page:2})
  assert.equal(calls[2].filters.includeTalkers,false)
  await loader.load('applications',{})
  assert.equal(calls.length,3)
  assert.equal(commits.length,3)
  loader.dispose()
})

test('superseded mapping filters abort the request and cannot commit stale topology',async()=>{
  const requests=[],commits=[]
  const service={listTopology:(filters,options)=>new Promise(resolve=>requests.push({filters,options,resolve}))}
  const loader=createMappingLoader(service,{commit:(_tab,result)=>commits.push(result),setLoading:()=>{},onError:error=>{throw error}})
  const old=loader.load('topology',{nodeId:'old'})
  const latest=loader.load('topology',{nodeId:'new'})
  assert.equal(requests[0].options.signal.aborted,true)
  requests[1].resolve({marker:'new'});await latest
  requests[0].resolve({marker:'old'});await old
  assert.deepEqual(commits,[{marker:'new'}])
  loader.dispose()
})
