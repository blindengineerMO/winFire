exports.up=async knex=>{
  await knex.schema.alterTable('directory_connections',table=>table.text('action_credential_id').references('id').inTable('credentials').onDelete('SET NULL'))
  await knex.schema.createTable('ad_account_holds',table=>{
    table.text('id').primary()
    table.text('user_guid').notNullable().references('id').inTable('directory_users')
    table.integer('expected_uac').notNullable()
    table.text('expires_at').notNullable()
    table.text('status').notNullable().defaultTo('active')
    table.text('created_by')
    table.text('created_at').notNullable()
    table.text('resolved_at')
    table.text('last_attempt_at')
    table.text('error')
  })
  await knex.raw("CREATE INDEX idx_ad_account_holds_due ON ad_account_holds(status,expires_at)")
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_ad_account_holds_due')
  await knex.schema.dropTableIfExists('ad_account_holds')
  await knex.schema.alterTable('directory_connections',table=>table.dropColumn('action_credential_id'))
}
