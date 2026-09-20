export async function pollFleet(nodes,work,{concurrency=4,onError=()=>{}}={}){
  const requested=Number(concurrency)
  const workers=Math.min(nodes.length,20,Math.max(1,Number.isFinite(requested)?Math.floor(requested)||1:4))
  let next=0
  await Promise.all(Array.from({length:workers},async()=>{
    while(next<nodes.length){
      const node=nodes[next++]
      try{await work(node)}catch(error){await onError(error,node)}
    }
  }))
}
