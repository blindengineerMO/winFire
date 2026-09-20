exports.up=async knex=>{
  await knex.schema.createTable('mfa_public_entra_flows',table=>{
    table.text('state_hash').primary()
    table.text('prompt_id').notNullable().references('id').inTable('mfa_prompt_events').onDelete('CASCADE')
    table.text('source_ip').notNullable()
    table.text('sealed_checks').notNullable()
    table.text('challenge_id').notNullable().references('id').inTable('mfa_challenges').onDelete('CASCADE')
    table.text('expires_at').notNullable()
    table.text('used_at')
  })
  await knex.raw('CREATE INDEX idx_mfa_public_entra_due ON mfa_public_entra_flows(expires_at,used_at)')
}
exports.down=async knex=>{await knex.schema.dropTableIfExists('mfa_public_entra_flows')}
