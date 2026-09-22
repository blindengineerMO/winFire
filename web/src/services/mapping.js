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
  collectArp: nodeId => api(`/nodes/${nodeId}/arp/collect`, {method: 'POST'})
}
