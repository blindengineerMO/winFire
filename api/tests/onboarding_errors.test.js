import test from 'node:test'
import assert from 'node:assert/strict'
import {classifyOnboardingError,attachOnboardingError} from '../src/onboardingErrors.js'

test('onboarding errors map common management failures to stable remediation categories',()=>{
  assert.equal(classifyOnboardingError(new Error('WinRM denied access'),{operation:'probe'}).code,'auth_rejected')
  assert.equal(classifyOnboardingError(new Error('Cannot generate SSPI context for the target SPN')).code,'kerberos_spn_double_hop')
  assert.equal(classifyOnboardingError(new Error('WinRM service is not running')).code,'winrm_listener_disabled')
  assert.equal(classifyOnboardingError(new Error('WMI did not confirm access to Win32_ComputerSystem')).code,'wmi_dcom_blocked')
  assert.equal(classifyOnboardingError(new Error('No supported management port responded'),{ports:{winrm:{status:'refused'},winrms:{status:'timeout'},wmi:{status:'unreachable'},smb:{status:'refused'}}}).code,'port_closed')
})

test('onboarding error attachment preserves the original diagnostic and adds structured guidance',()=>{
  const error=attachOnboardingError(new Error('access denied while opening WMI'),{operation:'activate_winrm',transport:'wmi'})
  assert.equal(error.onboardingError.code,'auth_rejected')
  assert.equal(error.onboardingError.operation,'activate_winrm')
  assert.match(error.onboardingError.remediation,/username|password|account/i)
  assert.equal(error.message,'access denied while opening WMI')
})
