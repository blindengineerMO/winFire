exports.up=async knex=>{
  await knex.schema.createTable('process_exclusions',table=>{
    table.text('name').primary()
    table.text('added_at').notNullable()
  })
}

exports.down=async knex=>knex.schema.dropTableIfExists('process_exclusions')
