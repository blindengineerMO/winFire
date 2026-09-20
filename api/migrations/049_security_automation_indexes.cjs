exports.up=async knex=>{
  await knex.raw('CREATE INDEX idx_security_events_dst_received ON log_events(dst_ip,received_at)')
  await knex.raw('CREATE INDEX idx_security_events_received ON log_events(received_at)')
  await knex.raw('CREATE INDEX idx_security_mfa_status_time ON mfa_challenges(status,resolved_at,user_upn)')
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_security_mfa_status_time')
  await knex.raw('DROP INDEX IF EXISTS idx_security_events_received')
  await knex.raw('DROP INDEX IF EXISTS idx_security_events_dst_received')
}
