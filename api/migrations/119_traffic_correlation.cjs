exports.up=async k=>{
  await k.raw('CREATE INDEX idx_traffic_observation_event ON traffic_observations(event_id)')
  await k.schema.createTable('traffic_correlations',t=>{
    t.text('observation_id').primary().references('id').inTable('traffic_observations').onDelete('CASCADE')
    t.text('status').notNullable().defaultTo('pending')
    t.text('endpoint_event_id').references('id').inTable('log_events').onDelete('SET NULL')
    t.text('endpoint_reference');t.integer('delta_ms');t.text('reason');t.integer('attempts').notNullable().defaultTo(0)
    t.text('next_attempt_at').notNullable();t.text('updated_at').notNullable();t.index(['status','next_attempt_at'])
  })
  await k.raw("CREATE TRIGGER traffic_correlation_enqueue AFTER INSERT ON traffic_observations BEGIN INSERT INTO traffic_correlations(observation_id,next_attempt_at,updated_at) VALUES(NEW.id,strftime('%Y-%m-%dT%H:%M:%fZ','now'),strftime('%Y-%m-%dT%H:%M:%fZ','now')); END")
  await k('app_settings').insert({key:'traffic_correlation_backfill',value:'0'})
}
exports.down=async k=>{
  await k.raw('DROP TRIGGER IF EXISTS traffic_correlation_enqueue')
  await k.raw('DROP INDEX IF EXISTS idx_traffic_observation_event')
  await k.schema.dropTable('traffic_correlations')
  await k('app_settings').where({key:'traffic_correlation_backfill'}).del()
}
