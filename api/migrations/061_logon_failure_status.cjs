exports.up=async knex=>{
  await knex.schema.alterTable('log_events',table=>{
    table.text('logon_status')
    table.text('logon_sub_status')
  })
  await knex.raw('CREATE INDEX idx_log_events_lsa_denied ON log_events(node_id,event_id,logon_status,account_sid,received_at)')
}

exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_log_events_lsa_denied')
  await knex.schema.alterTable('log_events',table=>{
    table.dropColumn('logon_status')
    table.dropColumn('logon_sub_status')
  })
}
