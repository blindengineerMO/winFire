exports.up = async knex => {
  for (const [name, add] of [
    ['name', table => table.text('name').notNullable().defaultTo('CIDR discovery schedule')],
    ['status', table => table.text('status').notNullable().defaultTo('enabled')],
    ['running_since', table => table.text('running_since')]
  ]) {
    if (!(await knex.schema.hasColumn('discovery_scan_schedules', name))) await knex.schema.alterTable('discovery_scan_schedules', add)
  }
  await knex.raw("UPDATE discovery_scan_schedules SET status=CASE WHEN enabled=1 THEN 'enabled' ELSE 'paused' END WHERE status IS NULL OR status=''")
  await knex.raw("UPDATE discovery_scan_schedules SET name='CIDR discovery schedule' WHERE name IS NULL OR name=''")
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_discovery_schedule_claim ON discovery_scan_schedules(enabled,status,next_run_at)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_discovery_schedule_claim')
  for (const name of ['running_since','status','name']) {
    if (await knex.schema.hasColumn('discovery_scan_schedules', name)) await knex.schema.alterTable('discovery_scan_schedules', table => table.dropColumn(name))
  }
}
