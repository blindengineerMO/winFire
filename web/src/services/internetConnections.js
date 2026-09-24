import {api,download} from './api.js'
export const internetConnections={
  list:query=>api(`/internet/connections?${query}`),
  details:id=>api(`/internet/connections/${encodeURIComponent(id)}`),
  peer:id=>api(`/internet/peers/${encodeURIComponent(id)}`),
  resolve:id=>api(`/internet/peers/${encodeURIComponent(id)}/resolve`,{method:'POST'}),
  export:query=>download(`/internet/connections/export?${query}`,'internet-connections.json'),
  rule:(id,body)=>api(`/logs/${encodeURIComponent(id)}/rule`,{method:'POST',body}),
  ignore:id=>api(`/logs/${encodeURIComponent(id)}/ignore-traffic`,{method:'POST'})
}
