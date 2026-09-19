import {diffRules} from './connector.js'

export function classifyVerification(rule, probeStatus, managedRulePresent) {
  if (!['allow','block'].includes(rule.action)) return {status:'inconclusive',reason:'Unsupported firewall action'}
  if (rule.action === 'allow') {
    if (probeStatus === 'open') return {status:'pass',reason:'TCP connection opened'}
    if (probeStatus === 'refused') return {status:'fail',reason:'Target refused the connection; service and firewall state need inspection'}
    return {status:'inconclusive',reason:'Target or network did not respond'}
  }
  if (probeStatus === 'open') return {status:'fail',reason:'TCP connection opened despite deny policy'}
  if (managedRulePresent === true && ['refused','timeout'].includes(probeStatus)) {
    return {status:'pass',reason:'Managed deny rule is present and the TCP connection did not open'}
  }
  return {status:'inconclusive',reason:managedRulePresent === false
    ? 'Managed deny rule is missing or differs from the policy'
    : 'TCP did not open; managed rule could not be confirmed'}
}

export function hasManagedRule(rule, actualRules) {
  const matching=(actualRules||[]).filter(actual=>actual.name===rule.name)
  return matching.length===1 && diffRules([rule],matching).add.length===0
}
