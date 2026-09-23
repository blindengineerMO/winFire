exports.up = async knex => {
  for (const [name, builder] of [
    ['identity_json', table => table.text('identity_json').notNullable().defaultTo('{}')],
    ['routes_json', table => table.text('routes_json').notNullable().defaultTo('{}')],
    ['tcp_states_json', table => table.text('tcp_states_json').notNullable().defaultTo('{}')]
  ]) {
    if (!(await knex.schema.hasColumn('network_table_snapshots', name))) await knex.schema.alterTable('network_table_snapshots', builder)
  }
}

exports.down = async knex => {
  for (const name of ['tcp_states_json', 'routes_json', 'identity_json']) {
    if (await knex.schema.hasColumn('network_table_snapshots', name)) await knex.schema.alterTable('network_table_snapshots', table => table.dropColumn(name))
  }
}
