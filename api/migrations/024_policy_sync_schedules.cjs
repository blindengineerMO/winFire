exports.up=async knex=>{
  await knex.schema.createTable('policy_sync_schedules',table=>{
    table.text('id').primary()
    table.text('requested_by').references('id').inTable('users').onDelete('SET NULL')
    table.text('execute_at').notNullable()
    table.text('status').notNullable().defaultTo('scheduled')
    table.text('result_json')
    table.text('created_at').notNullable().defaultTo(knex.fn.now())
    table.text('finished_at')
  })
  await knex.raw('CREATE INDEX idx_policy_sync_due ON policy_sync_schedules(status,execute_at)')
}
exports.down=async knex=>{await knex.schema.dropTableIfExists('policy_sync_schedules')}
