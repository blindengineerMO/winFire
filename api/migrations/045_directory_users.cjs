exports.up=async knex=>{
  await knex.schema.createTable('directory_users',table=>{
    table.text('id').primary()
    table.text('sid').unique()
    table.text('dn').notNullable()
    table.text('sam_account_name')
    table.text('upn')
    table.text('email')
    table.text('display_name')
    table.text('member_of_json')
    table.boolean('enabled').notNullable().defaultTo(true)
    table.boolean('missing').notNullable().defaultTo(false)
    table.text('last_logon_at')
    table.text('changed_at')
    table.text('seen_at').notNullable()
  })
  await knex.raw('CREATE INDEX idx_directory_users_search ON directory_users(sam_account_name,display_name,email)')
  await knex.raw('CREATE INDEX idx_directory_users_upn ON directory_users(upn)')
  await knex.schema.alterTable('users',table=>{
    table.text('auth_source').notNullable().defaultTo('local')
    table.text('ad_guid')
  })
  await knex.raw('CREATE UNIQUE INDEX idx_users_ad_guid ON users(ad_guid) WHERE ad_guid IS NOT NULL')
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_users_ad_guid')
  await knex.schema.alterTable('users',table=>{table.dropColumn('auth_source');table.dropColumn('ad_guid')})
  await knex.raw('DROP INDEX IF EXISTS idx_directory_users_upn')
  await knex.raw('DROP INDEX IF EXISTS idx_directory_users_search')
  await knex.schema.dropTableIfExists('directory_users')
}
