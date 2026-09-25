import {Router} from 'express'
import {keyOptions,listKeys,createKey,editKey,rotateKey,removeKey} from '../services/userApiKeys.js'
import {mcpResourceUrl} from '../ai/mcp.js'
export const apiKeyRoutes=Router()
apiKeyRoutes.use((req,res,next)=>{res.set('Cache-Control','no-store');if(req.apiKey)return res.status(403).json({error:'Sign in with your user account to administer API keys'});next()})
apiKeyRoutes.get('/options',(req,res)=>res.json({...keyOptions(req.user),mcpUrl:mcpResourceUrl()}))
apiKeyRoutes.get('/',(req,res)=>res.json(listKeys(req.user,req.query)))
apiKeyRoutes.post('/',(req,res)=>res.status(201).json(createKey(req.user,req.body)))
apiKeyRoutes.patch('/:id',(req,res)=>res.json(editKey(req.user,req.params.id,req.body)))
apiKeyRoutes.post('/:id/rotate',(req,res)=>res.json(rotateKey(req.user,req.params.id)))
apiKeyRoutes.post('/:id/revoke',(req,res)=>res.json(removeKey(req.user,req.params.id,{revoke:true})))
apiKeyRoutes.delete('/:id',(req,res)=>{removeKey(req.user,req.params.id);res.status(204).end()})
