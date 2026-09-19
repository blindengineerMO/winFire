import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
import Database from 'better-sqlite3'
import knexFactory from 'knex'

const dataDir = path.resolve(process.env.DATA_DIR || 'data')
fs.mkdirSync(dataDir, {recursive:true, mode:0o700})
const migrationClient = knexFactory({
  client: 'better-sqlite3',
  connection: {filename: path.join(dataDir, 'winfire.db')},
  useNullAsDefault: true,
  migrations: {directory: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../migrations'), extension: 'cjs'}
})
await migrationClient.migrate.latest()
await migrationClient.destroy()

export const db = new Database(path.join(dataDir, 'winfire.db'))
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')

export const one = (sql, ...args) => db.prepare(sql).get(...args)
export const all = (sql, ...args) => db.prepare(sql).all(...args)
export const run = (sql, ...args) => db.prepare(sql).run(...args)
export const json = value => JSON.stringify(value ?? null)
export const parse = value => value ? JSON.parse(value) : null
export const now = () => new Date().toISOString()
export const id = () => crypto.randomUUID()
export function audit(actor, action, entityType, entityId, before, after) {
  run('INSERT INTO audit_log(id,actor_user_id,action,entity_type,entity_id,before_json,after_json,at) VALUES(?,?,?,?,?,?,?,?)', id(), actor || null, action, entityType, entityId || null, json(before), json(after), now())
}
