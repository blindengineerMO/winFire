exports.up=async k=>{
 await k.schema.createTable('servicenow_integration',t=>{t.integer('id').primary();t.text('config_json').notNullable();t.text('updated_at').notNullable()})
 await k.schema.createTable('servicenow_tickets',t=>{t.text('correlation_id').primary();t.text('event_key').notNullable();t.text('instance_url').notNullable();t.text('sys_id');t.text('number');t.text('created_at').notNullable()})
 await k.schema.createTable('ddos_policies',t=>{t.text('id').primary();t.text('name').notNullable();t.text('config_json').notNullable();t.text('created_at').notNullable();t.text('updated_at').notNullable()})
 await k.schema.createTable('ddos_incidents',t=>{
  t.text('id').primary();t.text('policy_id').notNullable().references('id').inTable('ddos_policies');t.text('node_id').notNullable()
  t.text('status').notNullable();t.text('evidence_json').notNullable();t.text('block_json');t.integer('cycles').notNullable().defaultTo(0)
  t.text('created_at').notNullable();t.text('updated_at').notNullable();t.text('expires_at');t.text('observe_after');t.text('last_error');t.text('closed_at');t.index(['status','expires_at'])
 })
 await k.raw('CREATE UNIQUE INDEX ddos_active_node ON ddos_incidents(node_id) WHERE closed_at IS NULL')
 await k.schema.createTable('ddos_transitions',t=>{t.text('id').primary();t.text('incident_id').notNullable().references('id').inTable('ddos_incidents');t.text('status').notNullable();t.text('detail_json').notNullable();t.text('created_at').notNullable()})
}
exports.down=async k=>{for(const t of ['ddos_transitions','ddos_incidents','ddos_policies','servicenow_tickets','servicenow_integration'])await k.schema.dropTableIfExists(t)}
