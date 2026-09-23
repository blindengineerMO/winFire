/** Persist the relationship between discovered assets and hypervisor guests. */
exports.up = async knex => {
  for (const [name, builder] of [
    ['virtual_machine', table => table.integer('virtual_machine').notNullable().defaultTo(0)],
    ['virtual_machine_host_id', table => table.text('virtual_machine_host_id').references('id').inTable('nodes').onDelete('SET NULL')],
    ['virtual_machine_details_json', table => table.text('virtual_machine_details_json')]
  ]) {
    if (!(await knex.schema.hasColumn('nodes', name))) await knex.schema.alterTable('nodes', builder)
  }
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_nodes_virtual_machine_host ON nodes(virtual_machine_host_id)')
  // SQLite rebuilds a table for some ALTER operations and may drop triggers.
  // Reassert the global policy membership trigger so newly discovered assets
  // continue to inherit global policy assignments.
  await knex.raw(`CREATE TRIGGER IF NOT EXISTS winfire_global_group_new_node AFTER INSERT ON nodes BEGIN
    INSERT OR IGNORE INTO node_group_members(group_id,node_id) VALUES('winfire-global-all-nodes',NEW.id);
  END`)
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_nodes_virtual_machine_host')
  for (const name of ['virtual_machine_details_json','virtual_machine_host_id','virtual_machine']) {
    if (await knex.schema.hasColumn('nodes', name)) await knex.schema.alterTable('nodes', table => table.dropColumn(name))
  }
}
