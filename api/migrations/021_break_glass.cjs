exports.up = async knex => {
  await knex.schema.createTable('break_glass_sessions', table => {
    table.text('id').primary()
    table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('actor_user_id').notNullable()
    table.text('reason').notNullable()
    table.text('started_at').notNullable()
    table.text('expires_at').notNullable()
    table.text('status').notNullable()
    table.text('profile_snapshot_json')
    table.text('agent_job_id')
    table.text('ended_at')
    table.text('last_error')
  })
  await knex.raw("CREATE UNIQUE INDEX idx_break_glass_one_active ON break_glass_sessions(node_id) WHERE status IN ('activating','activation-unknown','active','ending')")
  await knex.raw('CREATE INDEX idx_break_glass_due ON break_glass_sessions(status,expires_at)')
}
exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_break_glass_due')
  await knex.raw('DROP INDEX IF EXISTS idx_break_glass_one_active')
  await knex.schema.dropTable('break_glass_sessions')
}
