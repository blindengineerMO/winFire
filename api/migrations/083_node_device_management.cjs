exports.up = async knex => {
  for (const [name, builder] of [
    ['device_type', table => table.text('device_type').notNullable().defaultTo('auto')],
    ['management_type', table => table.text('management_type').notNullable().defaultTo('auto')],
    ['collect_network_tables', table => table.integer('collect_network_tables').notNullable().defaultTo(0)]
  ]) {
    if (!(await knex.schema.hasColumn('nodes', name))) await knex.schema.alterTable('nodes', builder)
  }
}

exports.down = async knex => {
  for (const name of ['collect_network_tables', 'management_type', 'device_type']) {
    if (await knex.schema.hasColumn('nodes', name)) await knex.schema.alterTable('nodes', table => table.dropColumn(name))
  }
}
