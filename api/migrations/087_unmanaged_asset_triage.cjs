exports.up = async knex => {
  if (!(await knex.schema.hasColumn('nodes', 'first_discovered_at'))) await knex.schema.alterTable('nodes', table => table.text('first_discovered_at'))
  if (!(await knex.schema.hasColumn('nodes', 'last_managed_at'))) await knex.schema.alterTable('nodes', table => table.text('last_managed_at'))
  if (!(await knex.schema.hasColumn('nodes', 'triage_status'))) await knex.schema.alterTable('nodes', table => table.text('triage_status').notNullable().defaultTo('none'))
  if (!(await knex.schema.hasColumn('nodes', 'triage_note'))) await knex.schema.alterTable('nodes', table => table.text('triage_note'))
  if (!(await knex.schema.hasColumn('nodes', 'triage_updated_at'))) await knex.schema.alterTable('nodes', table => table.text('triage_updated_at'))
  if (!(await knex.schema.hasColumn('nodes', 'triage_updated_by'))) await knex.schema.alterTable('nodes', table => table.text('triage_updated_by').references('id').inTable('users').onDelete('SET NULL'))
  await knex.raw("UPDATE nodes SET first_discovered_at=COALESCE(first_discovered_at,last_discovered_at,created_at) WHERE first_discovered_at IS NULL")
  await knex('app_settings').insert({key:'unmanaged_asset_window_days',value:'7'}).onConflict('key').ignore()
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_nodes_triage ON nodes(agent_required,triage_status,first_discovered_at,last_managed_at)')
  // SQLite table rebuilds used by ALTER TABLE can drop triggers attached to
  // nodes. Recreate the global membership trigger so newly discovered nodes
  // continue to inherit the global policy scope.
  await knex.raw(`CREATE TRIGGER IF NOT EXISTS winfire_global_group_new_node AFTER INSERT ON nodes BEGIN
    INSERT OR IGNORE INTO node_group_members(group_id,node_id) VALUES('winfire-global-all-nodes',NEW.id);
  END`)
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_nodes_triage')
  await knex('app_settings').where({key:'unmanaged_asset_window_days'}).del()
  for (const name of ['triage_updated_by','triage_updated_at','triage_note','triage_status','last_managed_at','first_discovered_at']) {
    if (await knex.schema.hasColumn('nodes', name)) await knex.schema.alterTable('nodes', table => table.dropColumn(name))
  }
}
