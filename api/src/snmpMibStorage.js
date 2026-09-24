import fs from 'node:fs'
import path from 'node:path'
import {createHash,randomUUID} from 'node:crypto'
import multer from 'multer'
import {z} from 'zod'
import {all,one,run,now} from './db.js'
export const mibLibraryDir=path.resolve(process.env.SNMP_MIB_LIBRARY_DIR||path.join(process.env.DATA_DIR||'data','snmp-mibs'))
const staging=path.join(mibLibraryDir,'.uploads')
fs.mkdirSync(staging,{recursive:true,mode:0o700})
export const maxUploadBytes=8*1024*1024
export function sourcePath(relative){
  if(!/^[a-f0-9]{2}\/[a-f0-9]{64}\.mib$/.test(relative||''))throw new Error('Invalid MIB storage key')
  return path.join(mibLibraryDir,relative)
}
export function storeSource(content){
  const bytes=Buffer.isBuffer(content)?content:Buffer.from(content),sha256=createHash('sha256').update(bytes).digest('hex'),relative=sha256.slice(0,2)+'/'+sha256+'.mib',dest=sourcePath(relative)
  fs.mkdirSync(path.dirname(dest),{recursive:true,mode:0o700})
  if(!fs.existsSync(dest)){const temp=path.join(staging,randomUUID());try{fs.writeFileSync(temp,bytes,{mode:0o600,flag:'wx'});fs.renameSync(temp,dest)}finally{fs.rmSync(temp,{force:true})}}
  return {sourcePath:relative,sha256,size:bytes.length}
}
export function readSource(row){return row.source_path?fs.readFileSync(sourcePath(row.source_path),'utf8'):row.content}
export function migrateMibSources(){
  for(const row of all('SELECT id,module_name,filename,content FROM snmp_mib_library WHERE content IS NOT NULL AND source_path IS NULL')){const stored=recordMibFile({moduleName:row.module_name,filename:row.filename||row.module_name+'.mib',content:row.content});run('UPDATE snmp_mib_library SET source_path=?,content=NULL WHERE id=?',stored.sourcePath,row.id)}
}
const receive=multer({storage:multer.diskStorage({destination:staging,filename:(_req,_file,cb)=>cb(null,randomUUID())}),limits:{fileSize:maxUploadBytes,files:20,fields:2,fieldSize:1024,parts:22}}).array('files',20)
export const cleanupMibUploads=req=>{for(const f of req.files||[])fs.rmSync(f.path,{force:true})}
export function mibUpload(req,res,next){
  if(!req.is('multipart/form-data'))return next()
  receive(req,res,error=>{if(error){cleanupMibUploads(req);return res.status(error.code==='LIMIT_FILE_SIZE'?413:400).json({error:error instanceof multer.MulterError?`MIB upload rejected: ${error.message}`:'Unable to store MIB upload'})}next()})
}
export function mibUploadInput(req){
  if(!req.is('multipart/form-data'))return req.body
  if(req.body.replace&&!['true','false'].includes(req.body.replace))throw Object.assign(new Error('replace must be true or false'),{status:400})
  const files=req.files||[]
  if(files.reduce((n,f)=>n+f.size,0)>32*1024*1024)throw Object.assign(new Error('Upload batch exceeds 32 MiB'),{status:413})
  return {replace:req.body.replace==='true',files:files.map(f=>({filename:f.originalname,content:fs.readFileSync(f.path,'utf8')}))}
}
export function listMibFiles(query={}){
  const {search,status,page,limit}=z.object({search:z.string().max(200).default(''),status:z.enum(['all','ready','archived','error','pending','bundled']).default('all'),page:z.coerce.number().int().min(1).default(1),limit:z.coerce.number().int().min(1).max(100).default(25)}).parse(query)
  const parts=[],args=[];if(search){parts.push('(filename LIKE ? OR module_name LIKE ?)');args.push('%'+search+'%','%'+search+'%')}if(status!=='all'){parts.push('status=?');args.push(status)}
  const where=parts.length?'WHERE '+parts.join(' AND '):'',total=one('SELECT count(*) n FROM snmp_mib_files '+where,...args).n,actualPage=Math.min(page,Math.max(1,Math.ceil(total/limit)))
  return {items:all('SELECT id,module_name AS moduleName,filename,size,sha256,origin,source_url AS sourceUrl,revision,status,error FROM snmp_mib_files '+where+' ORDER BY filename,id LIMIT ? OFFSET ?',...args,limit,(actualPage-1)*limit),total,page:actualPage,limit}
}
export function recordMibFile({moduleName,filename,content,origin='upload',sourceUrl=null,revision=null,status='ready',error=null}){
  const stored=storeSource(content),id=createHash('sha256').update(origin+'\0'+filename).digest('hex')
  run('INSERT INTO snmp_mib_files(id,module_name,filename,source_path,sha256,size,origin,source_url,revision,status,error,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(origin,filename) DO UPDATE SET module_name=excluded.module_name,source_path=excluded.source_path,sha256=excluded.sha256,size=excluded.size,source_url=excluded.source_url,revision=excluded.revision,status=excluded.status,error=excluded.error',id,moduleName||null,filename,stored.sourcePath,stored.sha256,stored.size,origin,sourceUrl,revision,status,error,now())
  return {id,...stored}
}
