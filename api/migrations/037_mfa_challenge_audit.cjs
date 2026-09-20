exports.up=async knex=>{
  await knex.schema.alterTable('mfa_challenges',table=>{
    table.text('provider')
    table.text('failure_reason')
    table.text('prompt_id')
  })
  await knex.schema.alterTable('mfa_entra_flows',table=>table.text('challenge_id'))
  await knex.raw('CREATE INDEX idx_mfa_challenges_pending_expiry ON mfa_challenges(status,expires_at)')
}

exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_mfa_challenges_pending_expiry')
  await knex.schema.alterTable('mfa_entra_flows',table=>table.dropColumn('challenge_id'))
  await knex.schema.alterTable('mfa_challenges',table=>{
    table.dropColumn('provider')
    table.dropColumn('failure_reason')
    table.dropColumn('prompt_id')
  })
}
