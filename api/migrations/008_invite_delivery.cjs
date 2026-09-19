exports.up = knex => knex.schema.alterTable('invites', table => {
  table.text('delivered_at')
  table.text('created_by')
})

exports.down = knex => knex.schema.alterTable('invites', table => {
  table.dropColumn('delivered_at')
  table.dropColumn('created_by')
})
