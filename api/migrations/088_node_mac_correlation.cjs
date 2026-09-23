exports.up = async knex => {
  if (!(await knex.schema.hasColumn('nodes', 'mac_address'))) {
    await knex.schema.alterTable('nodes', table => table.text('mac_address'))
  }
  // ARP observations collected before this migration are still useful as an
  // identity source for nodes whose address has changed.
  await knex.raw("UPDATE nodes SET mac_address=lower(replace((SELECT a.mac FROM arp_entries a WHERE lower(a.ip)=lower(nodes.ip) AND a.mac IS NOT NULL ORDER BY a.observed_at DESC LIMIT 1),'-',':')) WHERE mac_address IS NULL AND ip IS NOT NULL")
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_nodes_mac_address ON nodes(mac_address)')
  // SQLite table rebuilds used by ALTER TABLE can remove the global group
  // trigger. Keep newly discovered nodes in the global policy scope.
  await knex.raw(`CREATE TRIGGER IF NOT EXISTS winfire_global_group_new_node AFTER INSERT ON nodes BEGIN
    INSERT OR IGNORE INTO node_group_members(group_id,node_id) VALUES('winfire-global-all-nodes',NEW.id);
  END`)
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_nodes_mac_address')
  if (await knex.schema.hasColumn('nodes', 'mac_address')) await knex.schema.alterTable('nodes', table => table.dropColumn('mac_address'))
}
