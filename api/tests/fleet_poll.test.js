import test from 'node:test'
import assert from 'node:assert/strict'
import {pollFleet} from '../src/fleetPoll.js'

test('a simulated 10,000-node fleet stays within its WinRM concurrency budget',async()=>{
  const nodes=Array.from({length:10_000},(_,index)=>index)
  const seen=new Set(),failures=[]
  let active=0,peak=0
  await pollFleet(nodes,async node=>{
    active++;peak=Math.max(active,peak)
    await Promise.resolve()
    seen.add(node)
    active--
    if(node===6000)throw Error('one unreachable node')
  },{concurrency:4,onError:(error,node)=>failures.push({message:error.message,node})})
  assert.equal(peak,4)
  assert.equal(seen.size,10_000)
  assert.deepEqual(failures,[{message:'one unreachable node',node:6000}])
})
