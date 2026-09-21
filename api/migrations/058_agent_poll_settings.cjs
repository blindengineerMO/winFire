exports.up=async knex=>{
  await knex.schema.createTable('agent_poll_settings',table=>{
    table.text('target_type').notNullable()
    table.text('target_id').notNullable()
    table.integer('poll_seconds').notNullable()
    table.text('updated_at').notNullable()
    table.primary(['target_type','target_id'])
  })
}

exports.down=async knex=>knex.schema.dropTableIfExists('agent_poll_settings')
