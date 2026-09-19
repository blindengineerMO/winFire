import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import {one,run} from './db.js'

const directory=path.resolve(process.env.DATA_DIR||'data','avatars')
const formats={
  'image/png':{extension:'png',valid:bytes=>bytes.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex'))},
  'image/jpeg':{extension:'jpg',valid:bytes=>bytes.length>4&&bytes.subarray(0,3).equals(Buffer.from('ffd8ff','hex'))&&bytes.subarray(-2).equals(Buffer.from('ffd9','hex'))},
  'image/webp':{extension:'webp',valid:bytes=>bytes.length>12&&bytes.toString('ascii',0,4)==='RIFF'&&bytes.toString('ascii',8,12)==='WEBP'}
}

function avatarPath(userId,extension) {return path.join(directory,`${userId}.${extension}`)}

export function saveAvatar(userId,mimeType,base64) {
  const format=formats[mimeType]
  if(!format||typeof base64!=='string'||base64.length>700_000||base64.length%4!==0||!/^[A-Za-z0-9+/]+={0,2}$/.test(base64))throw Object.assign(new Error('Invalid avatar format'),{status:400})
  const bytes=Buffer.from(base64,'base64')
  if(bytes.length<16||bytes.length>512*1024||!format.valid(bytes))throw Object.assign(new Error('Avatar must be a PNG, JPEG or WebP image under 512 KB'),{status:400})
  fs.mkdirSync(directory,{recursive:true,mode:0o700})
  const target=avatarPath(userId,format.extension),temporary=path.join(directory,`.${userId}.${crypto.randomUUID()}.tmp`)
  fs.writeFileSync(temporary,bytes,{mode:0o600})
  fs.renameSync(temporary,target)
  for(const {extension} of Object.values(formats))if(extension!==format.extension)fs.rmSync(avatarPath(userId,extension),{force:true})
  const url=`/api/v1/avatars/${userId}?v=${Date.now()}`
  run('UPDATE user_profiles SET avatar_url=? WHERE user_id=?',url,userId)
  return url
}

export function readAvatar(userId) {
  if(!/^[0-9a-f-]{36}$/i.test(userId)||!one('SELECT avatar_url FROM user_profiles WHERE user_id=? AND avatar_url IS NOT NULL',userId))return null
  for(const [mimeType,{extension}] of Object.entries(formats)){
    const file=avatarPath(userId,extension)
    if(fs.existsSync(file))return {mimeType,bytes:fs.readFileSync(file)}
  }
  return null
}

export function removeAvatar(userId) {
  run('UPDATE user_profiles SET avatar_url=NULL WHERE user_id=?',userId)
  for(const {extension} of Object.values(formats))fs.rmSync(avatarPath(userId,extension),{force:true})
}
