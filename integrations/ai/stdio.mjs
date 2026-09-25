import {serveStdio} from '@modelcontextprotocol/server/stdio'
import {McpServer} from '@modelcontextprotocol/server'
import {eventSchema,batchSchema,receiptSchema} from '../../api/src/ai/schemas.js'
import {AiReporter} from './reporter.mjs'
// Importing the adapter never opens an inventory database. Credentials remain in the environment.
const reporter=new AiReporter()
serveStdio(()=>{
 const s=new McpServer({name:'winfire-ai-usage-stdio',version:'1.0.0'})
 const send=async data=>{
  try{
   const response=await reporter.fetch(reporter.baseUrl+'/api/v1/ai/usage:batch',{method:'POST',headers:{Authorization:'Bearer '+reporter.credential,'Content-Type':'application/json'},body:JSON.stringify(data),signal:AbortSignal.timeout(5000),redirect:'error'})
   if(!response.ok)throw Error('unavailable')
   const receipt=receiptSchema.parse(await response.json())
   return {isError:receipt.results.some(r=>r.status==='rejected'),content:[{type:'text',text:JSON.stringify(receipt)}],structuredContent:receipt}
  }catch{
   let buffered=0;for(const raw of data.events){const parsed=eventSchema.safeParse(raw);if(parsed.success&&reporter.record(parsed.data))buffered++}
   return {isError:true,content:[{type:'text',text:`No durable receipt confirmed. ${buffered} valid reports buffered locally; retry with the same event IDs or run flush.mjs.`}]}
  }
 }
 const annotations={readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}
 s.registerTool('report_ai_usage',{description:'Write one AI metadata report. Only a durable receipt confirms acceptance.',inputSchema:eventSchema,outputSchema:receiptSchema,annotations},e=>send({events:[e]}))
 s.registerTool('report_ai_usage_batch',{description:'Write up to 100 AI metadata reports with per-event durable receipts.',inputSchema:batchSchema,outputSchema:receiptSchema,annotations},send)
 return s
})
