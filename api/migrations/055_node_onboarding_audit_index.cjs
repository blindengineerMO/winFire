exports.up=async knex=>{
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_audit_node_onboarding ON audit_log(entity_id,action)')
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_audit_node_onboarding')
}
