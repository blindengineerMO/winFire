exports.up = async knex => {
  for (const [name, builder] of [
    ['os_name', table => table.text('os_name')],
    ['hypervisor', table => table.text('hypervisor')],
    ['manageability', table => table.text('manageability').notNullable().defaultTo('managed')],
    ['snmp_capable', table => table.integer('snmp_capable').notNullable().defaultTo(0)]
  ]) {
    if (!(await knex.schema.hasColumn('nodes', name))) await knex.schema.alterTable('nodes', builder)
  }
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_nodes_hypervisor ON nodes(hypervisor)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_nodes_hypervisor')
  for (const name of ['snmp_capable','manageability','hypervisor','os_name']) {
    if (await knex.schema.hasColumn('nodes', name)) await knex.schema.alterTable('nodes', table => table.dropColumn(name))
  }
}
