// Keep just the current result per resource. A tab change never waits on hidden
// graphs/tables; changing filters cannot render a previous request's response.
export function createMappingLoader(service,{commit,setLoading,onError}){
  const loaded=new Map()
  let controller=null,sequence=0,disposed=false
  async function load(tab,filters,{page=1,pageSize=100,force=false}={}){
    const current=++sequence
    controller?.abort()
    controller=new AbortController()
    setLoading(false)
    if(disposed||['applications','cloud'].includes(tab))return
    const filterKey=JSON.stringify(filters),key=tab==='pairs'?`${filterKey}:${page}:${pageSize}`:filterKey
    if(!force&&loaded.get(tab)===key)return
    setLoading(true)
    try{
      const options={signal:controller.signal}
      let result
      if(tab==='pairs')result=await service.listPairs({...filters,page,pageSize,includeTalkers:false},options)
      else if(tab==='topology')result=await service.listTopology(filters,options)
      else if(tab==='talkers')result=await service.listTalkers(filters,options)
      else if(tab==='neighbors')result=await service.listArp(filters,options)
      else return
      if(current!==sequence||disposed)return
      commit(tab,result)
      loaded.set(tab,key)
    }catch(error){if(current===sequence&&!disposed&&error.name!=='AbortError')onError(error)}
    finally{if(current===sequence&&!disposed)setLoading(false)}
  }
  return {load,dispose(){disposed=true;sequence++;controller?.abort()},invalidate(){loaded.clear()}}
}
