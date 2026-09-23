import {api} from './api.js'

export const mappingService = {
  listNodes: () => api('/nodes'),
  listPairs: ({page, pageSize, nodeId, external, trafficClass}) => {
    const query = new URLSearchParams({page: String(page), pageSize: String(pageSize)})
    if (nodeId) query.set('nodeId', nodeId)
    if (external) query.set('external', external)
    if (trafficClass) query.set('trafficClass', trafficClass)
    return api(`/mapping?${query}`)
  },
  listArp: nodeId => api(`/mapping/arp${nodeId ? `?nodeId=${encodeURIComponent(nodeId)}` : ''}`),
  rebuild: () => api('/mapping/rebuild', {method: 'POST'}),
  collectArp: nodeId => api(`/nodes/${nodeId}/arp/collect`, {method: 'POST'}),
  findRepresentativeEvent: row => {
    const nodeId=row.direction==='in'?row.destination_node_id:row.source_node_id
    if(!nodeId||!['in','out'].includes(row.direction)||!row.source_ip||!row.destination_ip)return Promise.resolve(null)
    const query=new URLSearchParams({eventType:'firewall',nodeId,direction:row.direction,srcIp:row.source_ip,dstIp:row.destination_ip,page:'1',pageSize:'25',hideLoopback:'false'})
    if(row.destination_port)query.set('port',String(row.destination_port))
    return api(`/logs/search?${query}`).then(result=>result.items.find(event=>String(event.protocol||'').toUpperCase()===String(row.protocol||'').toUpperCase())||result.items[0]||null)
  },
  createRule: (eventId, action, policyId) => api(`/logs/${eventId}/rule`, {method:'POST',body:{action,...(policyId&&policyId!=='personal'?{policyId}: {})}}),
  ignoreEvent: eventId => api(`/logs/${eventId}/ignore-traffic`, {method:'POST'})
}
