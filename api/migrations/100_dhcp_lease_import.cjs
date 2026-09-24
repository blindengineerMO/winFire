exports.up = async knex => {
  await knex.schema.alterTable('nodes', table => table.text('dhcp_lease_json'))
  await knex.schema.createTable('dhcp_lease_imports', table => {
    table.text('id').primary()
    table.text('fingerprint').notNullable().unique()
    table.text('source').notNullable()
    table.text('observed_at').notNullable()
    table.text('imported_at').notNullable()
    table.text('summary_json').notNullable()
    table.text('rows_json').notNullable()
  })
}
exports.down = async knex => {
  await knex.schema.dropTableIfExists('dhcp_lease_imports')
  await knex.schema.alterTable('nodes', table => table.dropColumn('dhcp_lease_json'))
}
