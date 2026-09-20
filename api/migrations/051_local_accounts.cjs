exports.up=async knex=>{
  await knex.schema.createTable('local_accounts',table=>{
    table.text('id').primary()
    table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('sid').notNullable()
    table.text('username').notNullable()
    table.text('qualified_name').notNullable()
    table.text('full_name')
    table.text('description')
    table.boolean('enabled').notNullable().defaultTo(true)
    table.boolean('locked').notNullable().defaultTo(false)
    table.boolean('password_required')
    table.boolean('missing').notNullable().defaultTo(false)
    table.text('seen_at').notNullable()
    table.unique(['node_id','sid'])
  })
  await knex.schema.createTable('sid_resolutions',table=>{
    table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('sid').notNullable()
    table.text('qualified_name').notNullable()
    table.text('seen_at').notNullable()
    table.primary(['node_id','sid'])
  })
  await knex.raw('CREATE INDEX idx_local_accounts_name ON local_accounts(username,qualified_name)')
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_local_accounts_name')
  await knex.schema.dropTableIfExists('sid_resolutions')
  await knex.schema.dropTableIfExists('local_accounts')
}
