exports.up=async k=>{
  await k.schema.createTable('evidence_destinations',t=>{
    t.text('id').primary();t.text('name').notNullable();t.text('endpoint').notNullable();t.text('secret_blob').notNullable()
    t.text('scope_id').notNullable().references('id').inTable('inventory_scopes');t.boolean('enabled').notNullable().defaultTo(false)
    t.integer('interval_minutes').notNullable();t.text('event_types_json').notNullable();t.text('next_run_at').notNullable()
    t.bigInteger('audit_cursor').notNullable();t.integer('revision').notNullable().defaultTo(1)
    t.text('created_at').notNullable();t.text('updated_at').notNullable();t.text('last_error')
  })
  await k.schema.createTable('evidence_deliveries',t=>{
    t.text('id').primary();t.text('destination_id').notNullable().references('id').inTable('evidence_destinations').onDelete('CASCADE')
    t.text('event_key').notNullable();t.text('payload_json').notNullable();t.integer('revision').notNullable()
    t.text('status').notNullable().defaultTo('pending');t.integer('attempts').notNullable().defaultTo(0)
    t.text('next_attempt_at').notNullable();t.text('created_at').notNullable();t.text('sent_at');t.text('last_error')
    t.unique(['destination_id','event_key']);t.index(['status','next_attempt_at'])
  })
}
exports.down=async k=>{await k.schema.dropTable('evidence_deliveries');await k.schema.dropTable('evidence_destinations')}
