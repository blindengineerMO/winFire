import {ref, watch} from 'vue'
import {api} from '../services/api.js'

export function useDhcpImport() {
  const content=ref(''), result=ref(null), history=ref({items:[],page:1,totalPages:1}), busy=ref(false), error=ref(''), ready=ref(false)
  watch(content,()=>{result.value=null;ready.value=false})
  async function load(page=1) {
    try { history.value=await api(`/discovery/dhcp/imports?page=${page}&pageSize=25`) }
    catch(cause){error.value=cause.message}
  }
  async function readFile(event) {
    error.value=''
    const file=event.target.files?.[0]
    if(!file)return
    if(file.size>1500000){error.value='Export at most 2,000 leases in a file smaller than 1.5 MB.';return}
    content.value=await file.text()
  }
  async function submit(commit=false) {
    busy.value=true;error.value='';ready.value=false
    try {
      let payload
      try { payload=JSON.parse(content.value.replace(/^\uFEFF/,'')) } catch { throw new Error('Choose a JSON file produced by Export-DhcpLeases.ps1, or paste its JSON contents.') }
      result.value=await api(`/discovery/dhcp/${commit?'import':'preview'}`,{method:'POST',body:payload})
      ready.value=!commit&&(result.value.summary.created+result.value.summary.enriched>0)
      if(commit)await load()
    }catch(cause){error.value=cause.message}
    finally{busy.value=false}
  }
  async function inspect(importId) {
    busy.value=true;error.value='';ready.value=false
    try{result.value=await api(`/discovery/dhcp/imports/${importId}`)}catch(cause){error.value=cause.message}finally{busy.value=false}
  }
  return {content,result,history,busy,error,ready,load,readFile,submit,inspect}
}
