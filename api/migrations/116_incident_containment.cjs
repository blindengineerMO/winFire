exports.up=async k=>{
 await k.schema.createTable('containment_jobs',t=>{t.text('id').primary();t.text('status').notNullable();t.text('config_json').notNullable();t.text('requested_by').notNullable();t.text('created_at').notNullable();t.text('expires_at').notNullable();t.text('updated_at').notNullable();t.text('lease_until');t.text('error')})
 await k.schema.createTable('containment_targets',t=>{t.text('job_id').notNullable().references('id').inTable('containment_jobs');t.text('node_id').notNullable().references('id').inTable('nodes');t.text('transaction_id').notNullable();t.text('status').notNullable().defaultTo('pending');t.text('snapshot_json');t.text('error');t.primary(['job_id','node_id'])})
}
exports.down=async k=>{await k.schema.dropTable('containment_targets');await k.schema.dropTable('containment_jobs')}
