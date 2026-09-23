exports.up = async knex => {
  for (const [name,builder] of [
    ['discovery_ttl', table => table.integer('discovery_ttl')],
    ['discovery_os_family', table => table.text('discovery_os_family')]
  ]) {
    if (!(await knex.schema.hasColumn('nodes',name))) await knex.schema.alterTable('nodes',builder)
  }
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_nodes_discovery_os_family ON nodes(discovery_os_family)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_nodes_discovery_os_family')
  for (const name of ['discovery_os_family','discovery_ttl']) {
    if (await knex.schema.hasColumn('nodes',name)) await knex.schema.alterTable('nodes',table=>table.dropColumn(name))
  }
}
