exports.up=async knex=>{
  await knex.schema.alterTable('verifier_results',table=>{
    table.text('probe_source_ip')
    table.integer('probe_source_port')
    table.integer('firewall_event_record_id')
    table.text('firewall_event_time')
  })
  await knex.raw('CREATE INDEX idx_verifier_event_tuple ON log_events(node_id,event_id,src_port,event_time)')
}

exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_verifier_event_tuple')
  await knex.schema.alterTable('verifier_results',table=>{
    table.dropColumn('probe_source_ip')
    table.dropColumn('probe_source_port')
    table.dropColumn('firewall_event_record_id')
    table.dropColumn('firewall_event_time')
  })
}
