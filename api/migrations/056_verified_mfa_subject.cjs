exports.up=async knex=>{
  await knex.schema.alterTable('mfa_challenges',table=>{
    table.text('verified_account_sid')
    table.text('verified_at')
    table.text('verified_method')
    table.text('failure_kind')
  })
  await knex.raw('CREATE INDEX idx_verified_mfa_failure ON mfa_challenges(status,failure_kind,resolved_at,verified_account_sid)')
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_verified_mfa_failure')
  await knex.schema.alterTable('mfa_challenges',table=>{
    table.dropColumn('verified_account_sid')
    table.dropColumn('verified_at')
    table.dropColumn('verified_method')
    table.dropColumn('failure_kind')
  })
}
