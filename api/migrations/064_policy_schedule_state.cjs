exports.up=async knex=>{
  await knex.schema.createTable('policy_schedule_state',table=>{
    table.text('policy_id').notNullable().references('id').inTable('policies').onDelete('CASCADE')
    table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('state_key').notNullable()
    table.text('last_applied_at').notNullable()
    table.primary(['policy_id','node_id'])
  })
  await knex.raw('CREATE INDEX idx_policy_schedule_state_node ON policy_schedule_state(node_id,last_applied_at)')
}

exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_policy_schedule_state_node')
  await knex.schema.dropTableIfExists('policy_schedule_state')
}
