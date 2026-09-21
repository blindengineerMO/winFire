exports.up=async knex=>{
  await knex.schema.alterTable('agent_poll_settings',table=>{
    table.text('channel_mode').notNullable().defaultTo('pull')
  })
}

exports.down=async knex=>{
  await knex.schema.alterTable('agent_poll_settings',table=>{
    table.dropColumn('channel_mode')
  })
}
