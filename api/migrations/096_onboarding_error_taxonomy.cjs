exports.up = async knex => {
  if (!(await knex.schema.hasColumn('nodes', 'onboarding_error_code'))) await knex.schema.alterTable('nodes', table => table.text('onboarding_error_code'))
  if (!(await knex.schema.hasColumn('nodes', 'onboarding_error_updated_at'))) await knex.schema.alterTable('nodes', table => table.text('onboarding_error_updated_at'))
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_nodes_onboarding_error ON nodes(onboarding_error_code,onboarding_error_updated_at)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_nodes_onboarding_error')
  for (const name of ['onboarding_error_updated_at', 'onboarding_error_code']) {
    if (await knex.schema.hasColumn('nodes', name)) await knex.schema.alterTable('nodes', table => table.dropColumn(name))
  }
}
