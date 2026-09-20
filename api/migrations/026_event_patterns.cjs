exports.up=async knex=>{
  await knex('app_settings').insert([
    {key:'hide_loopback_events',value:'true'},
    {key:'ignore_loopback_ingest',value:'false'},
    {key:'event_compact_hours',value:'24'}
  ])
  await knex.schema.createTable('event_patterns',table=>{
    table.text('id').primary()
    table.text('fingerprint').notNullable().unique()
    table.text('action')
    table.text('protocol')
    table.text('src_ip')
    table.text('dst_ip')
    table.integer('dst_port')
    table.text('direction')
    table.text('program')
    table.text('event_type')
    table.text('created_at').notNullable().defaultTo(knex.fn.now())
  })
  await knex.raw('ALTER TABLE log_events ADD COLUMN pattern_id TEXT REFERENCES event_patterns(id) ON DELETE SET NULL')
  await knex.raw('CREATE INDEX idx_log_events_pattern ON log_events(pattern_id)')
  await knex.raw('CREATE INDEX idx_log_event_compact_due ON log_events(pattern_id,datetime(COALESCE(event_time,received_at)))')
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_log_events_pattern')
  await knex.raw('DROP INDEX IF EXISTS idx_log_event_compact_due')
  await knex.raw('ALTER TABLE log_events DROP COLUMN pattern_id')
  await knex.schema.dropTableIfExists('event_patterns')
  await knex('app_settings').whereIn('key',['hide_loopback_events','ignore_loopback_ingest','event_compact_hours']).del()
}
