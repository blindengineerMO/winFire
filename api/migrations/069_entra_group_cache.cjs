exports.up=async knex=>{
  await knex.schema.createTable('entra_group_members',table=>{
    table.text('group_id').notNullable()
    table.text('object_id').notNullable()
    table.text('upn')
    table.text('email')
    table.boolean('enabled').notNullable().defaultTo(true)
    table.text('seen_at').notNullable()
    table.text('expires_at').notNullable()
    table.primary(['group_id','object_id'])
  })
  await knex.schema.createTable('entra_group_sync',table=>{
    table.text('group_id').primary()
    table.text('synced_at').notNullable()
    table.text('expires_at').notNullable()
    table.text('last_error')
  })
  await knex.schema.raw('CREATE INDEX entra_group_members_identity ON entra_group_members(group_id, upn, email)')
}
exports.down=async knex=>{
  await knex.schema.dropTableIfExists('entra_group_members')
  await knex.schema.dropTableIfExists('entra_group_sync')
}
