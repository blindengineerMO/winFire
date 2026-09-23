exports.up = async knex => {
  if (!(await knex.schema.hasTable('discovery_scan_schedules'))) {
    await knex.schema.createTable('discovery_scan_schedules', table => {
      table.text('id').primary()
      table.text('cidrs_json').notNullable()
      table.integer('interval_minutes').notNullable().defaultTo(60)
      table.integer('enabled').notNullable().defaultTo(1)
      table.text('next_run_at').notNullable()
      table.text('last_run_at')
      table.text('last_scan_id')
      table.text('last_status')
      table.text('last_error')
      table.text('created_by').references('id').inTable('users').onDelete('SET NULL')
      table.text('created_at').notNullable()
      table.text('updated_at').notNullable()
    })
    await knex.raw('CREATE INDEX idx_discovery_schedule_due ON discovery_scan_schedules(enabled,next_run_at)')
  }
  for (const [name, add] of [
    ['schedule_id', table => table.text('schedule_id').references('id').inTable('discovery_scan_schedules').onDelete('SET NULL')],
    ['diff_json', table => table.text('diff_json').notNullable().defaultTo('{}')]
  ]) {
    if (!(await knex.schema.hasColumn('discovery_scans', name))) await knex.schema.alterTable('discovery_scans', add)
  }
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_discovery_scan_schedule ON discovery_scans(schedule_id,created_at)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_discovery_scan_schedule')
  if (await knex.schema.hasColumn('discovery_scans', 'diff_json')) await knex.schema.alterTable('discovery_scans', table => table.dropColumn('diff_json'))
  if (await knex.schema.hasColumn('discovery_scans', 'schedule_id')) await knex.schema.alterTable('discovery_scans', table => table.dropColumn('schedule_id'))
  await knex.raw('DROP INDEX IF EXISTS idx_discovery_schedule_due')
  await knex.schema.dropTableIfExists('discovery_scan_schedules')
}
