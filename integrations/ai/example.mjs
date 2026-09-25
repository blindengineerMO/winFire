import {AiReporter} from './reporter.mjs'
const reporter=new AiReporter()
await reporter.track({operation:'research',provider:'local',model:'example',tool:'example.research'},async()=>{
 // Substitute the instrumented task here. Its input and result are not reported.
 return {completed:true}
})
await reporter.flush();await reporter.heartbeat()
console.log(JSON.stringify(reporter.health))
