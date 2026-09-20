function portIntervals(value) {
  if (!value || value === 'Any') return [[1,65535]]
  return String(value).split(',').map(piece => {
    const [start,end=start]=piece.split('-').map(Number)
    return [start,end]
  })
}

function portsOverlap(left,right) {
  return portIntervals(left).some(([a,b])=>portIntervals(right).some(([c,d])=>a<=d && c<=b))
}

function scopeOverlaps(left,right) {
  if (!left || !right || left === 'Any' || right === 'Any') return true
  if (String(left).toLowerCase() === String(right).toLowerCase()) return true
  // Distinct single IPv4 addresses cannot match the same packet. Other address
  // expressions may overlap, so keep the result conservative.
  const ipv4=/^(?:\d{1,3}\.){3}\d{1,3}$/
  if (ipv4.test(left) && ipv4.test(right)) return false
  return true
}

function exactScopeOverlaps(left,right) {
  return !left || !right || left === 'Any' || right === 'Any' || String(left).toLowerCase() === String(right).toLowerCase()
}

export function rulesConflict(left,right) {
  if(!!left.localUserSid!==!!right.localUserSid)return false
  if(left.localUserSid&&right.localUserSid&&left.localUserSid!==right.localUserSid)return false
  return left.action !== right.action
    && left.direction === right.direction
    && (left.protocol === right.protocol || left.protocol === 'Any' || right.protocol === 'Any')
    && portsOverlap(left.localPort,right.localPort)
    && portsOverlap(left.remotePort,right.remotePort)
    && scopeOverlaps(left.remoteAddress,right.remoteAddress)
    && exactScopeOverlaps(left.program,right.program)
    && exactScopeOverlaps(left.profile,right.profile)
}

export function findRuleConflicts(leftRules,rightRules) {
  const conflicts=[]
  for(const left of leftRules)for(const right of rightRules)if(rulesConflict(left,right))conflicts.push({rule:left.name,otherRule:right.name,port:left.direction==='out'?left.remotePort:left.localPort,otherPort:right.direction==='out'?right.remotePort:right.localPort})
  return conflicts
}
