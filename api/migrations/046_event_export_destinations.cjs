exports.up=async knex=>{
  await knex.schema.createTable('event_export_destinations',table=>{
    table.text('id').primary()
    table.text('name').notNullable()
    table.text('kind').notNullable()
    table.text('endpoint').notNullable()
    table.text('token_blob')
    table.text('created_at').notNullable()
    table.text('updated_at').notNullable()
  })
}
exports.down=async knex=>knex.schema.dropTableIfExists('event_export_destinations')
