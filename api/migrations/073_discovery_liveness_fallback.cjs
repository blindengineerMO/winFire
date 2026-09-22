exports.up = async knex => {
  for (const name of ['arp_alive', 'tcp_alive']) {
    if (!(await knex.schema.hasColumn('discovery_scans', name))) {
      await knex.schema.alterTable('discovery_scans', table => table.integer(name).notNullable().defaultTo(0))
    }
  }
}

exports.down = async knex => {
  for (const name of ['tcp_alive', 'arp_alive']) {
    if (await knex.schema.hasColumn('discovery_scans', name)) {
      await knex.schema.alterTable('discovery_scans', table => table.dropColumn(name))
    }
  }
}
