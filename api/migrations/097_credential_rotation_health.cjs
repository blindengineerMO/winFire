/** Track credential authentication health so rotated secrets are detected as one incident. */
exports.up = async knex => {
  const hasTable = await knex.schema.hasTable('credential_auth_health')
  if (!hasTable) {
    await knex.schema.createTable('credential_auth_health', table => {
      table.text('credential_id').notNullable().references('id').inTable('credentials').onDelete('CASCADE')
      table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
      table.text('last_success_at')
      table.text('last_success_transport')
      table.text('last_auth_failure_at')
      table.text('failure_code')
      table.integer('failure_count').notNullable().defaultTo(0)
      table.primary(['credential_id', 'node_id'])
    })
  }
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_credential_auth_health_failure ON credential_auth_health(credential_id,last_auth_failure_at,failure_code)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_credential_auth_health_failure')
  await knex.schema.dropTableIfExists('credential_auth_health')
}
