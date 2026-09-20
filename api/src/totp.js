import crypto from 'node:crypto'

const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export function base32(bytes) {
  let bits=0,value=0,result=''
  for(const byte of bytes){value=(value<<8)|byte;bits+=8;while(bits>=5){result+=alphabet[(value>>>(bits-5))&31];bits-=5}}
  if(bits>0)result+=alphabet[(value<<(5-bits))&31]
  return result
}
export function makeTotpSecret(){return base32(crypto.randomBytes(20))}
function decodeBase32(value){let bits=0,acc=0,result=[];for(const char of value.toUpperCase().replace(/=+$/,'')){const n=alphabet.indexOf(char);if(n<0)throw new Error('Invalid TOTP secret');acc=(acc<<5)|n;bits+=5;if(bits>=8){result.push((acc>>>(bits-8))&255);bits-=8}}return Buffer.from(result)}
export function totpCode(secret,time=Date.now()){
  const counter=BigInt(Math.floor(time/30000)),buffer=Buffer.alloc(8);buffer.writeBigUInt64BE(counter)
  const mac=crypto.createHmac('sha1',decodeBase32(secret)).update(buffer).digest(),offset=mac.at(-1)&15
  return String((mac.readUInt32BE(offset)&0x7fffffff)%1000000).padStart(6,'0')
}
export function verifyTotp(secret,code){
  if(!/^\d{6}$/.test(String(code||'')))return false
  const provided=Buffer.from(String(code))
  return [-30000,0,30000].some(delta=>crypto.timingSafeEqual(Buffer.from(totpCode(secret,Date.now()+delta)),provided))
}
export function matchingTotpCounter(secret,code,time=Date.now()){
  if(!/^\d{6}$/.test(String(code||'')))return null
  const supplied=Buffer.from(String(code)),counter=Math.floor(time/30000)
  for(const offset of [-1,0,1])if(crypto.timingSafeEqual(Buffer.from(totpCode(secret,(counter+offset)*30000)),supplied))return counter+offset
  return null
}
