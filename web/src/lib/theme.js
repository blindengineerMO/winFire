import {ref} from 'vue'

const overrideKey='winfire_theme_override'
const prefersDark=window.matchMedia('(prefers-color-scheme: dark)')
let serverTheme='enterprise'
export const normalizeTheme=value=>value==='hacker'?'dark':value==='light'?'enterprise':value
const validTheme=value=>['system','dark','enterprise'].includes(normalizeTheme(value))?normalizeTheme(value):'system'
function readOverride(){try{return validTheme(localStorage.getItem(overrideKey))}catch{return 'system'}}
const browserPreference=ref(readOverride())
export const activeTheme=ref('enterprise')
export const localTheme=()=>browserPreference.value

export function applyTheme(preference=serverTheme){
  serverTheme=validTheme(preference)
  const choice=browserPreference.value==='system'?serverTheme:browserPreference.value
  activeTheme.value=choice==='system'?(prefersDark.matches?'dark':'enterprise'):choice
  document.documentElement.dataset.layout='enterprise'
  document.documentElement.dataset.theme=activeTheme.value
  document.documentElement.style.colorScheme=activeTheme.value==='dark'?'dark':'light'
}

export function setLocalTheme(value){
  browserPreference.value=validTheme(value)
  try{
    if(browserPreference.value==='system')localStorage.removeItem(overrideKey)
    else localStorage.setItem(overrideKey,browserPreference.value)
  }catch{/* Keep the choice usable when browser storage is unavailable. */}
  applyTheme()
}

prefersDark.addEventListener('change',()=>applyTheme())
window.addEventListener('storage',event=>{
  if(event.key===overrideKey||event.key===null){browserPreference.value=readOverride();applyTheme()}
})
applyTheme()
