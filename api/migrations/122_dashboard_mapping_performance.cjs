exports.up=async knex=>{
  // LIMIT can stop an ordered map read without sorting the complete map.
  await knex.raw('CREATE INDEX idx_map_rank ON network_map_pairs(connection_count DESC,last_seen_at DESC,map_key)')
  await knex.raw('CREATE INDEX idx_map_source_rank ON network_map_pairs(source_node_id,connection_count DESC,last_seen_at DESC,map_key)')
  await knex.raw('CREATE INDEX idx_map_destination_rank ON network_map_pairs(destination_node_id,connection_count DESC,last_seen_at DESC,map_key)')
  await knex.raw('DROP INDEX idx_network_map_source')
  await knex.raw('DROP INDEX idx_network_map_destination')
  await knex.raw('CREATE INDEX idx_verifier_node_latest ON verifier_results(node_id,run_at DESC)')
  await knex.raw('CREATE INDEX idx_drift_pair_latest ON policy_drift_checks(node_id,policy_id,version_id,datetime(checked_at) DESC)')
  await knex.raw('CREATE INDEX idx_arp_recent ON arp_entries(observed_at DESC,id)')
  await knex.raw('CREATE INDEX idx_arp_node_recent ON arp_entries(node_id,observed_at DESC,id)')
  // Also serves retention orphan checks; avoid rescanning every event per pattern.
  await knex.raw('CREATE INDEX idx_logs_pattern ON log_events(pattern_id)')
  await knex.raw('CREATE INDEX idx_logs_uncompacted ON log_events(received_at,id) WHERE pattern_id IS NULL')
}

exports.down=async knex=>{
  await knex.raw('CREATE INDEX idx_network_map_source ON network_map_pairs(source_node_id,connection_count)')
  await knex.raw('CREATE INDEX idx_network_map_destination ON network_map_pairs(destination_node_id,connection_count)')
  for(const name of ['idx_map_rank','idx_map_source_rank','idx_map_destination_rank','idx_verifier_node_latest','idx_drift_pair_latest','idx_arp_recent','idx_arp_node_recent','idx_logs_pattern','idx_logs_uncompacted'])await knex.raw(`DROP INDEX IF EXISTS ${name}`)
}
