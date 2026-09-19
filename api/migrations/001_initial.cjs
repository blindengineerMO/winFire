const fs = require('node:fs')
const path = require('node:path')

exports.up = async function up(knex) {
  const schema = fs.readFileSync(path.join(__dirname, '001_initial.sql'), 'utf8')
  for (const statement of schema.split(/;\s*\n/).map(value => value.trim()).filter(Boolean)) {
    await knex.raw(statement)
  }
}

exports.down = async function down() {
  throw new Error('Initial WinFire schema cannot be automatically removed. Restore a backup instead.')
}
