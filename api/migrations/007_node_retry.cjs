exports.up = knex => knex.schema.alterTable('nodes', table => {
  table.text('next_retry_at')
})

exports.down = knex => knex.schema.alterTable('nodes', table => {
  table.dropColumn('next_retry_at')
})
