import {ref} from 'vue'

const overrideKey='winfire_theme_override'
let serverTheme='enterprise'
const prefersLight=window.matchMedia('(prefers-color-scheme: light)')
export const activeTheme=ref('hacker')
export const normalizeTheme=value=>value==='dark'?'hacker':value==='light'?'enterprise':value

export function localTheme(){
  const value=normalizeTheme(localStorage.getItem(overrideKey))
  return ['system','hacker','enterprise'].includes(value)?value:'system'
}

export function applyTheme(preference=serverTheme){
  serverTheme=['system','hacker','enterprise'].includes(normalizeTheme(preference))?normalizeTheme(preference):'system'
  const choice=localTheme()==='system'?serverTheme:localTheme()
  activeTheme.value=choice==='system'?'enterprise':choice
  document.documentElement.dataset.theme=activeTheme.value
}

export function setLocalTheme(value){
  if(value==='system')localStorage.removeItem(overrideKey)
  else if(['hacker','enterprise'].includes(value))localStorage.setItem(overrideKey,value)
  applyTheme()
}

prefersLight.addEventListener('change',()=>applyTheme())
applyTheme()
