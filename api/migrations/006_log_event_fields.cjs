exports.up = knex => knex.schema.alterTable('log_events', table => {
  table.text('event_time')
  table.text('event_type')
  table.integer('src_port')
  table.text('logon_type')
})

exports.down = knex => knex.schema.alterTable('log_events', table => {
  table.dropColumn('event_time')
  table.dropColumn('event_type')
  table.dropColumn('src_port')
  table.dropColumn('logon_type')
})
