import crypto from 'node:crypto'

const eventIds = new Set([5150,5151,5156,5157,4624,4625,4634,4647,5712,4946,4947,4948,4949,4950,4951,4952,4953,4954,4955,4956,4957,528,529,530,531,532,533,534,535,536,537,538,539,540,551])

function decodeXml(value) {
  return String(value ?? '').replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (_match, entity) => {
    const key = entity.toLowerCase()
    if (key === 'amp') return '&'
    if (key === 'lt') return '<'
    if (key === 'gt') return '>'
    if (key === 'quot') return '"'
    if (key === 'apos') return "'"
    if (key.startsWith('#x')) return String.fromCodePoint(Number.parseInt(key.slice(2), 16))
    return String.fromCodePoint(Number.parseInt(key.slice(1), 10))
  })
}

function innerXml(xml, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = String(xml).match(new RegExp(`<(?:(?:[A-Za-z_][\\w.-]*):)?${escaped}\\b[^>]*>([\\s\\S]*?)</(?:(?:[A-Za-z_][\\w.-]*):)?${escaped}>`, 'i'))
  return match ? match[1] : null
}

function textIn(xml, name) {
  const value = innerXml(xml, name)
  return value === null ? null : decodeXml(value.replace(/<[^>]+>/g, '').trim())
}

function attribute(tag, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const match = String(tag).match(new RegExp(`\\b${escaped}\\s*=\\s*["']([^"']*)["']`, 'i'))
  return match ? decodeXml(match[1]) : null
}

function eventFragments(xml) {
  const fragments = []
  const source = String(xml)
  const start = /<(?:(?:[A-Za-z_][\w.-]*):)?Event(?:\s|>)/gi
  let match
  while ((match = start.exec(source))) {
    const openEnd = source.indexOf('>', match.index)
    if (openEnd < 0) break
    const openTag = source.slice(match.index, openEnd + 1)
    const close = new RegExp(`</(?:(?:[A-Za-z_][\\w.-]*):)?Event\\s*>`, 'ig')
    close.lastIndex = openEnd + 1
    const end = close.exec(source)
    if (!end) break
    fragments.push({xml: source.slice(match.index, end.index + end[0].length), attributes: openTag})
    start.lastIndex = end.index + end[0].length
  }
  return fragments
}

function parseEvent(fragment) {
  const xml = fragment.xml
  const system = innerXml(xml, 'System') || ''
  const eventId = Number(textIn(system, 'EventID'))
  const recordId = Number(textIn(system, 'EventRecordID'))
  const timeCreated = /<(?:(?:[A-Za-z_][\w.-]*):)?TimeCreated\b[^>]*>/i.exec(system)?.[0]
  const fields = {}
  const eventData = innerXml(xml, 'EventData') || innerXml(xml, 'UserData') || ''
  const dataPattern = /<(?:(?:[A-Za-z_][\w.-]*):)?Data\b([^>]*)>([\s\S]*?)<\/(?:(?:[A-Za-z_][\w.-]*):)?Data\s*>/gi
  let data
  while ((data = dataPattern.exec(eventData))) {
    const name = attribute(data[1], 'Name')
    if (name) fields[name] = decodeXml(data[2].replace(/<[^>]+>/g, '').trim())
  }
  if (!Number.isInteger(eventId) || !Number.isSafeInteger(recordId) || recordId < 1 || !eventIds.has(eventId)) return null
  return {
    RecordId: recordId,
    Id: eventId,
    TimeCreated: timeCreated ? attribute(timeCreated, 'SystemTime') : null,
    Fields: fields
  }
}

export function parseWefEvents(xml, {maxEvents = 500} = {}) {
  const source = String(xml ?? '')
  if (!source.trim()) throw Object.assign(new Error('WEF request body is empty'), {status: 400})
  if (source.length > 2 * 1024 * 1024) throw Object.assign(new Error('WEF request body is too large'), {status: 413})
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(source)) throw Object.assign(new Error('DOCTYPE and ENTITY declarations are not allowed'), {status: 400})
  const events = eventFragments(source).map(parseEvent).filter(Boolean)
  if (!events.length) throw Object.assign(new Error('WEF request contained no supported Windows Security events'), {status: 400})
  if (events.length > maxEvents) throw Object.assign(new Error(`WEF request contains more than ${maxEvents} events`), {status: 413})
  const seen = new Set()
  return events.filter(event => {
    const key = `${event.RecordId}:${event.Id}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export function timingSafeSecret(candidate, expected) {
  if (!candidate || !expected) return false
  const left = Buffer.from(String(candidate))
  const right = Buffer.from(String(expected))
  return left.length === right.length && crypto.timingSafeEqual(left, right)
}

export function wefNodeToken(secret, nodeId) {
  return crypto.createHmac('sha256', String(secret)).update(String(nodeId)).digest('base64url')
}

export function wefSubscriptionUrl(baseUrl, secret, nodeId, path = '/api/v1/wef/wsman') {
  const url = new URL(path, baseUrl)
  url.searchParams.set('token', wefNodeToken(secret, nodeId))
  url.searchParams.set('node', nodeId)
  return url.toString()
}

export function publicWefSettings({enabled, secretConfigured, baseUrl, path = '/api/v1/wef/wsman'}) {
  return {enabled: !!enabled, secretConfigured: !!secretConfigured, baseUrl: baseUrl || null, path}
}
