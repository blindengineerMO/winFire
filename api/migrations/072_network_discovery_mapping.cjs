exports.up = async knex => {
  if (!(await knex.schema.hasColumn('agents', 'capabilities_json'))) await knex.schema.alterTable('agents', table => table.text('capabilities_json').notNullable().defaultTo('{}'))
  const nodeColumns = [
    ['platform', table => table.text('platform')],
    ['agent_required', table => table.integer('agent_required').notNullable().defaultTo(0)],
    ['discovery_source', table => table.text('discovery_source')],
    ['last_discovered_at', table => table.text('last_discovered_at')],
    ['firewall_backend', table => table.text('firewall_backend')]
  ]
  for (const [name, add] of nodeColumns) {
    if (!(await knex.schema.hasColumn('nodes', name))) await knex.schema.alterTable('nodes', add)
  }

  await knex.schema.createTable('network_map_pairs', table => {
    table.text('map_key').primary()
    table.text('source_node_id').references('id').inTable('nodes').onDelete('SET NULL')
    table.text('destination_node_id').references('id').inTable('nodes').onDelete('SET NULL')
    table.text('source_ip').notNullable()
    table.text('destination_ip').notNullable()
    table.text('protocol').notNullable().defaultTo('UNKNOWN')
    table.integer('source_port')
    table.integer('destination_port')
    table.text('direction').notNullable().defaultTo('unknown')
    table.integer('external').notNullable().defaultTo(0)
    table.integer('connection_count').notNullable().defaultTo(0)
    table.text('sample_program')
    table.text('first_seen_at').notNullable()
    table.text('last_seen_at').notNullable()
    table.text('updated_at').notNullable()
  })
  await knex.schema.createTable('arp_entries', table => {
    table.text('id').primary()
    table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('ip').notNullable()
    table.text('mac')
    table.text('hostname')
    table.text('interface')
    table.text('state')
    table.text('source').notNullable().defaultTo('agent')
    table.text('observed_at').notNullable()
    table.unique(['node_id', 'ip', 'mac'])
  })
  await knex.schema.createTable('discovery_scans', table => {
    table.text('id').primary()
    table.text('cidrs_json').notNullable()
    table.text('status').notNullable().defaultTo('queued')
    table.integer('probed').notNullable().defaultTo(0)
    table.integer('alive').notNullable().defaultTo(0)
    table.integer('registered').notNullable().defaultTo(0)
    table.text('results_json').notNullable().defaultTo('[]')
    table.text('error')
    table.text('requested_by').references('id').inTable('users').onDelete('SET NULL')
    table.text('started_at')
    table.text('finished_at')
    table.text('created_at').notNullable()
  })
  await knex.raw('CREATE INDEX idx_network_map_last_seen ON network_map_pairs(last_seen_at)')
  await knex.raw('CREATE INDEX idx_network_map_source ON network_map_pairs(source_node_id,connection_count)')
  await knex.raw('CREATE INDEX idx_network_map_destination ON network_map_pairs(destination_node_id,connection_count)')
  await knex.raw('CREATE INDEX idx_arp_node_observed ON arp_entries(node_id,observed_at)')
  await knex.raw('CREATE INDEX idx_discovery_scan_status ON discovery_scans(status,created_at)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_discovery_scan_status')
  await knex.raw('DROP INDEX IF EXISTS idx_arp_node_observed')
  await knex.raw('DROP INDEX IF EXISTS idx_network_map_destination')
  await knex.raw('DROP INDEX IF EXISTS idx_network_map_source')
  await knex.raw('DROP INDEX IF EXISTS idx_network_map_last_seen')
  await knex.schema.dropTableIfExists('discovery_scans')
  await knex.schema.dropTableIfExists('arp_entries')
  await knex.schema.dropTableIfExists('network_map_pairs')
  for (const name of ['firewall_backend','last_discovered_at','discovery_source','agent_required','platform']) {
    if (await knex.schema.hasColumn('nodes', name)) await knex.schema.alterTable('nodes', table => table.dropColumn(name))
  }
}
