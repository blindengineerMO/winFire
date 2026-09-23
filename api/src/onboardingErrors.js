const definitions = {
  port_closed: {
    code: 'port_closed',
    title: 'Management port unavailable',
    summary: 'No supported management port is reachable on the host.',
    remediation: 'Confirm the host is online and allow TCP 135, 445, 5985, or 5986 from the control plane.'
  },
  auth_rejected: {
    code: 'auth_rejected',
    title: 'Credentials rejected',
    summary: 'The host rejected the supplied management credentials.',
    remediation: 'Verify the username, password, account status, and local or domain logon rights.'
  },
  kerberos_spn_double_hop: {
    code: 'kerberos_spn_double_hop',
    title: 'Kerberos, SPN, or delegation failure',
    summary: 'Kerberos could not establish the requested Windows management session.',
    remediation: 'Use the host FQDN, verify its SPN and clock synchronization, and review constrained delegation or use NTLM where appropriate.'
  },
  winrm_listener_disabled: {
    code: 'winrm_listener_disabled',
    title: 'WinRM listener unavailable',
    summary: 'WinRM is not listening or the WinRM service is disabled on the host.',
    remediation: 'Start the WinRM service and create an HTTP or HTTPS listener, then allow the selected port through the host firewall.'
  },
  wmi_dcom_blocked: {
    code: 'wmi_dcom_blocked',
    title: 'WMI/DCOM access blocked',
    summary: 'WMI or DCOM could not reach or authenticate the host.',
    remediation: 'Enable WMI, RPC endpoint mapper, and DCOM through the host firewall and confirm the account has remote WMI access.'
  },
  unknown: {
    code: 'unknown',
    title: 'Management verification failed',
    summary: 'The host did not complete management verification.',
    remediation: 'Review the host management configuration and run the probe again after correcting the reported condition.'
  }
}

export const ONBOARDING_ERROR_CODES = Object.freeze(Object.keys(definitions))
export const onboardingErrorForCode = code => definitions[code] || definitions.unknown

const textOf = error => String(error?.message || error || '').toLowerCase()
const anyPortOpen = ports => Object.values(ports || {}).some(port => String(port?.status || '').toLowerCase() === 'open')
const allPortsClosed = ports => {
  const values = Object.values(ports || {})
  return values.length > 0 && values.every(port => !['open', 'listening'].includes(String(port?.status || '').toLowerCase()))
}

export function classifyOnboardingError(error, context = {}) {
  const text = `${textOf(error)} ${textOf(context.message)}`
  const ports = context.ports || {}
  let code
  if (/kerberos|spn|double[ -]?hop|sspi|target principal|clock skew|delegat/i.test(text)) code = 'kerberos_spn_double_hop'
  else if (/access denied|access is denied|denied access|logon failure|logon denied|invalid (?:user|credential|password)|unauthori[sz]ed|bad password|credentials? rejected|authentication failed|0x8007052e|0xc000006d/i.test(text)) code = 'auth_rejected'
  else if (/wmi|dcom|rpc (?:server )?(?:unavailable|failed|error)|rpc endpoint|0x800706ba|0x800706be|firewall.*(block|deny)|blocked.*(firewall|dcom|rpc)/i.test(text)) code = 'wmi_dcom_blocked'
  else if (/winrm|wsman|listener|service.*(not running|disabled|stopped)|winrm cannot complete|0x80338126/i.test(text)) code = 'winrm_listener_disabled'
  else if (allPortsClosed(ports) || /no supported management port|connection refused|econnrefused|timed? out|etimedout|unreachable|port .* (closed|refused)|remains (?:unreachable|closed)/i.test(text)) code = 'port_closed'
  else code = 'unknown'
  return {...onboardingErrorForCode(code), transport: context.transport || null, operation: context.operation || null, observedOpenPort: anyPortOpen(ports)}
}

export function attachOnboardingError(error, context = {}) {
  const target = error instanceof Error ? error : new Error(String(error || 'Onboarding failed'))
  if (!target.onboardingError) target.onboardingError = classifyOnboardingError(target, context)
  return target
}
