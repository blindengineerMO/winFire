exports.up = async knex => {
  const columns = [
    ['dynamic_enabled', table => table.integer('dynamic_enabled').notNullable().defaultTo(0)],
    ['dynamic_match', table => table.text('dynamic_match').notNullable().defaultTo('all')],
    ['dynamic_rules_json', table => table.text('dynamic_rules_json').notNullable().defaultTo('[]')],
    ['dynamic_last_evaluated_at', table => table.text('dynamic_last_evaluated_at')],
    ['dynamic_next_evaluation_at', table => table.text('dynamic_next_evaluation_at')]
  ]
  for (const [name, add] of columns) {
    if (!(await knex.schema.hasColumn('node_groups', name))) await knex.schema.alterTable('node_groups', add)
  }
  await knex('app_settings').insert({key: 'dynamic_node_groups_interval_minutes', value: '60'}).onConflict('key').ignore()
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_node_groups_dynamic_due ON node_groups(dynamic_enabled,dynamic_next_evaluation_at)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_node_groups_dynamic_due')
  await knex('app_settings').where('key', 'dynamic_node_groups_interval_minutes').del()
  for (const name of ['dynamic_next_evaluation_at', 'dynamic_last_evaluated_at', 'dynamic_rules_json', 'dynamic_match', 'dynamic_enabled']) {
    if (await knex.schema.hasColumn('node_groups', name)) await knex.schema.alterTable('node_groups', table => table.dropColumn(name))
  }
}
