import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import {one,run} from './db.js'

const folder=path.resolve(process.env.DATA_DIR||'data','branding')
const formats={
  'image/png':{extension:'png',valid:b=>b.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex'))},
  'image/jpeg':{extension:'jpg',valid:b=>b.length>4&&b.subarray(0,3).equals(Buffer.from('ffd8ff','hex'))&&b.subarray(-2).equals(Buffer.from('ffd9','hex'))},
  'image/webp':{extension:'webp',valid:b=>b.length>12&&b.toString('ascii',0,4)==='RIFF'&&b.toString('ascii',8,12)==='WEBP'}
}
const imagePath=extension=>path.join(folder,`portal.${extension}`)
export function portalBranding(){
  const companyName=one("SELECT value FROM app_settings WHERE key='portal_company_name'")?.value||'WinFire Secure'
  const version=one("SELECT value FROM app_settings WHERE key='portal_image_version'")?.value
  return {companyName,imageUrl:version?`/api/v1/portal-branding/image?v=${encodeURIComponent(version)}`:null}
}
export function setPortalCompanyName(name){
  const value=String(name||'').trim()
  if(value.length<1||value.length>80||/[\x00-\x1f\x7f]/.test(value))throw Object.assign(new Error('Company name must contain 1–80 printable characters'),{status:400})
  run("INSERT INTO app_settings(key,value) VALUES('portal_company_name',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",value)
  return portalBranding()
}
export function savePortalImage(mimeType,base64){
  const format=formats[mimeType]
  if(!format||typeof base64!=='string'||base64.length>1_400_000||base64.length%4!==0||!/^[A-Za-z0-9+/]+={0,2}$/.test(base64))throw Object.assign(new Error('Invalid portal image'),{status:400})
  const bytes=Buffer.from(base64,'base64')
  if(bytes.length<16||bytes.length>1024*1024||!format.valid(bytes))throw Object.assign(new Error('Portal image must be PNG, JPEG, or WebP under 1 MB'),{status:400})
  fs.mkdirSync(folder,{recursive:true,mode:0o700})
  const target=imagePath(format.extension),temporary=path.join(folder,`.portal-${crypto.randomUUID()}.tmp`)
  fs.writeFileSync(temporary,bytes,{mode:0o600});fs.renameSync(temporary,target)
  for(const item of Object.values(formats))if(item.extension!==format.extension)fs.rmSync(imagePath(item.extension),{force:true})
  run("INSERT INTO app_settings(key,value) VALUES('portal_image_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",crypto.randomUUID())
  return portalBranding()
}
export function readPortalImage(){
  if(!one("SELECT value FROM app_settings WHERE key='portal_image_version'"))return null
  for(const [mimeType,format] of Object.entries(formats)){
    const filename=imagePath(format.extension)
    if(fs.existsSync(filename))return {mimeType,bytes:fs.readFileSync(filename)}
  }
  return null
}
export function removePortalImage(){
  run("DELETE FROM app_settings WHERE key='portal_image_version'")
  for(const item of Object.values(formats))fs.rmSync(imagePath(item.extension),{force:true})
  return portalBranding()
}
