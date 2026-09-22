import test from 'node:test'
import assert from 'node:assert/strict'
import {managementRuleViolation,assertManagementAccess} from '../src/managementGuard.js'

const options={controlIps:['192.0.2.10','2001:db8::10'],controlPort:3000}
const base={name:'candidate',action:'block',direction:'in',protocol:'TCP',localPort:'443',remotePort:'Any',remoteAddress:'Any'}
test('policy guard preserves WinRM and WinFire control-plane reachability',()=>{
  assert.match(managementRuleViolation({...base,localPort:'5980-5990'},options),/WinRM/)
  assert.match(managementRuleViolation({...base,localPort:'Any',remoteAddress:'198.51.100.0/24'},options),/WinRM/)
  assert.equal(managementRuleViolation({...base,localPort:'3389'},options),null)
  assert.match(managementRuleViolation({...base,direction:'out',remotePort:'3000',remoteAddress:'192.0.2.0/24'},options),/control plane/)
  assert.match(managementRuleViolation({...base,direction:'out',remotePort:'Any',remoteAddress:'2001:db8::/64'},options),/control plane/)
  assert.equal(managementRuleViolation({...base,direction:'out',remotePort:'3000',remoteAddress:'198.51.100.0/24'},options),null)
  assert.doesNotThrow(()=>assertManagementAccess([{...base,action:'allow',localPort:'5985'}],options))
  assert.throws(()=>assertManagementAccess([{...base,localPort:'5985'}],options),/WinRM/)
})
