import {AiReporter} from './reporter.mjs'
const reporter=new AiReporter()
await reporter.flush();await reporter.heartbeat()
console.log(JSON.stringify(reporter.health))
