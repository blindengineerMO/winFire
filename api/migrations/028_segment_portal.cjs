exports.up=async knex=>{
  await knex.schema.alterTable('identity_segments',table=>{
    table.text('mfa_provider').notNullable().defaultTo('totp')
    table.text('allowed_upns').notNullable().defaultTo('[]')
    table.boolean('portal_enabled').notNullable().defaultTo(true)
  })
  await knex.schema.createTable('mfa_totp_replay',table=>{
    table.text('user_id').primary().references('id').inTable('users').onDelete('CASCADE')
    table.bigInteger('last_counter').notNullable()
  })
}
exports.down=async knex=>{
  await knex.schema.dropTableIfExists('mfa_totp_replay')
  await knex.schema.alterTable('identity_segments',table=>{
    table.dropColumn('portal_enabled')
    table.dropColumn('allowed_upns')
    table.dropColumn('mfa_provider')
  })
}
