import {parseArgs} from 'node:util'
import {createRecoveryBackup,verifyRecoveryBackup,restoreRecoveryBackup,acknowledgeRecovery} from '../api/src/operations/recovery.js'
const {positionals,values}=parseArgs({allowPositionals:true,options:{'data-dir':{type:'string'},destination:{type:'string'},backup:{type:'string'},confirmation:{type:'string'}}})
try{
  let result
  if(positionals[0]==='backup'&&values['data-dir']&&values.destination)result=await createRecoveryBackup({dataDir:values['data-dir'],destination:values.destination})
  else if(positionals[0]==='verify'&&values.backup){const manifest=await verifyRecoveryBackup(values.backup);result={valid:true,createdAt:manifest.createdAt,files:manifest.files.length}}
  else if(positionals[0]==='restore'&&values.backup&&values.destination)result=await restoreRecoveryBackup({backup:values.backup,destination:values.destination})
  else if(positionals[0]==='acknowledge'&&values['data-dir'])result=acknowledgeRecovery(values['data-dir'],values.confirmation)
  else throw new Error('Use backup --data-dir PATH --destination NEW_PATH; verify --backup PATH; restore --backup PATH --destination NEW_PATH; or acknowledge --data-dir PATH --confirmation "REVIEWED RESTORED HOST STATE"')
  console.log(JSON.stringify(result,null,2))
}catch(error){console.error(error.message);process.exitCode=1}
