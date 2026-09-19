exports.up = async knex => {
  await knex.schema.alterTable('agents', table => {
    table.text('cert_expires_at')
    table.text('created_at').defaultTo(knex.fn.now())
  })
  await knex.schema.alterTable('agent_jobs', table => {
    table.text('lease_until')
    table.text('lease_token')
    table.integer('attempt_count').notNullable().defaultTo(0)
    table.text('error')
    table.text('result_json')
  })
}

exports.down = async knex => {
  await knex.schema.alterTable('agent_jobs', table => {
    table.dropColumn('lease_until')
    table.dropColumn('lease_token')
    table.dropColumn('attempt_count')
    table.dropColumn('error')
    table.dropColumn('result_json')
  })
  await knex.schema.alterTable('agents', table => {
    table.dropColumn('cert_expires_at')
    table.dropColumn('created_at')
  })
}
