import fs from 'node:fs'
import {fromOtlp} from './otel.mjs'
import {AiReporter} from './reporter.mjs'
// Offline OTLP JSON import; schedule flush.mjs independently of the agent's work.
try{const raw=fs.readFileSync(0,'utf8');if(Buffer.byteLength(raw)>4194304)throw Error();const reporter=new AiReporter();for(const event of fromOtlp(JSON.parse(raw)))reporter.record(event)}catch{process.stderr.write('AI metadata import failed; check configuration and OTLP JSON shape.\n');process.exitCode=1}
