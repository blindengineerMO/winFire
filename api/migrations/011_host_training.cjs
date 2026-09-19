exports.up = async knex => {
  await knex.schema.createTable('app_settings', table => {
    table.text('key').primary()
    table.text('value').notNullable()
  })
  await knex('app_settings').insert({key:'new_host_training_days',value:'30'})
  await knex.schema.alterTable('learning_sessions', table => {
    table.text('mode').notNullable().defaultTo('manual')
    table.text('last_attempt_at')
    table.text('last_error')
  })
  await knex.raw("CREATE INDEX idx_learning_due ON learning_sessions(mode,status,ends_at)")
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_learning_due')
  await knex.schema.alterTable('learning_sessions', table => {
    table.dropColumn('last_error')
    table.dropColumn('last_attempt_at')
    table.dropColumn('mode')
  })
  await knex.schema.dropTable('app_settings')
}
