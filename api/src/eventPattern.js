const ipv4Loopback=value=>/^127\.(?:\d{1,3}\.){2}\d{1,3}$/.test(value)
const loopback=value=>{
  const address=String(value||'').trim().toLowerCase()
  return address==='::1'||address==='0:0:0:0:0:0:0:1'||ipv4Loopback(address)||address.startsWith('::ffff:')&&ipv4Loopback(address.slice(7))
}
export const isLoopbackEvent=event=>loopback(event.srcIp??event.src_ip)&&loopback(event.dstIp??event.dst_ip)
