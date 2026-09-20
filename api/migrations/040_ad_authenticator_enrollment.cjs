exports.up=async knex=>{
  await knex.schema.alterTable('users',table=>table.boolean('directory_only').notNullable().defaultTo(false))
  await knex.schema.createTable('ad_authenticator_enrollments',table=>{
    table.text('token_hash').primary()
    table.text('email').notNullable()
    table.text('sealed_secret').notNullable()
    table.text('source_ip').notNullable()
    table.text('expires_at').notNullable()
    table.integer('attempts').notNullable().defaultTo(0)
  })
  await knex.schema.alterTable('ad_authenticator_enrollments',table=>table.index('email'))
}
exports.down=async knex=>{
  await knex.schema.dropTableIfExists('ad_authenticator_enrollments')
  await knex.schema.alterTable('users',table=>table.dropColumn('directory_only'))
}
