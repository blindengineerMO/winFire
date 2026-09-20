exports.up=async knex=>{
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_identity_logon_preview ON log_events(event_id, datetime(COALESCE(event_time,received_at)), node_id, account_sid)')
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_identity_logon_preview')
}
