import 'vue'
import test from 'node:test'
import assert from 'node:assert/strict'

// Exercise preference resolution without coupling tests to CSS or a browser engine.
const saved=new Map(),listeners={}
const media={matches:false,addEventListener:(_name,fn)=>{listeners.system=fn}}
globalThis.window={matchMedia:()=>media,addEventListener:(name,fn)=>{listeners[name]=fn}}
globalThis.document={documentElement:{dataset:{},style:{}}}
globalThis.localStorage={getItem:key=>saved.get(key)??null,setItem:(key,value)=>saved.set(key,value),removeItem:key=>saved.delete(key)}
const {applyTheme,setLocalTheme,localTheme,activeTheme,normalizeTheme}=await import('../../web/src/lib/theme.js')
const key='winfire_theme_override'

test('enterprise layout is preserved for both palettes and legacy theme names',()=>{
  for(const [preference,expected] of [['enterprise','enterprise'],['dark','dark'],['hacker','dark'],['light','enterprise']]){
    applyTheme(preference)
    assert.equal(activeTheme.value,expected)
    assert.equal(document.documentElement.dataset.layout,'enterprise')
    assert.equal(document.documentElement.style.colorScheme,expected==='dark'?'dark':'light')
  }
  assert.equal(normalizeTheme('hacker'),'dark')
})

test('system preference reacts to OS changes while explicit account preferences remain stable',()=>{
  applyTheme('system')
  media.matches=true;listeners.system()
  assert.equal(activeTheme.value,'dark')
  media.matches=false;listeners.system()
  assert.equal(activeTheme.value,'enterprise')
  applyTheme('dark');listeners.system()
  assert.equal(activeTheme.value,'dark')
})

test('browser override wins until cleared and changes in other tabs stay synchronized',()=>{
  applyTheme('enterprise')
  setLocalTheme('hacker')
  assert.equal(saved.get(key),'dark')
  assert.equal(localTheme(),'dark')
  applyTheme('enterprise')
  assert.equal(activeTheme.value,'dark')
  setLocalTheme('system')
  assert.equal(saved.has(key),false)
  assert.equal(activeTheme.value,'enterprise')
  saved.set(key,'dark');listeners.storage({key})
  assert.equal(activeTheme.value,'dark')
  saved.clear();listeners.storage({key:null})
  assert.equal(activeTheme.value,'enterprise')
})

test('unavailable browser storage does not break theme selection',()=>{
  const original=localStorage.setItem
  localStorage.setItem=()=>{throw new Error('Storage blocked')}
  try{setLocalTheme('dark');assert.equal(activeTheme.value,'dark')}finally{localStorage.setItem=original;setLocalTheme('system')}
})
