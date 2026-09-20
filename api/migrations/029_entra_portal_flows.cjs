exports.up=async knex=>{
  await knex.schema.createTable('mfa_entra_flows',table=>{
    table.text('state_hash').primary()
    table.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE')
    table.text('segment_id').notNullable().references('id').inTable('identity_segments').onDelete('CASCADE')
    table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('source_ip').notNullable()
    table.text('sealed_checks').notNullable()
    table.text('expires_at').notNullable()
    table.text('used_at')
  })
  await knex.raw('CREATE INDEX idx_entra_flows_due ON mfa_entra_flows(expires_at)')
}
exports.down=async knex=>{await knex.schema.dropTableIfExists('mfa_entra_flows')}
