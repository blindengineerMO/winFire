exports.up=async k=>{await k.schema.createTable('policy_host_context',t=>{t.text('node_id').primary().references('id').inTable('nodes').onDelete('CASCADE');t.text('captured_at').notNullable();t.text('snapshot_json').notNullable()})}
exports.down=async k=>{await k.schema.dropTable('policy_host_context')}
