exports.up=async k=>{
 await k.schema.createTable('vnet_blob_checkpoints',t=>{t.text('exporter_id').notNullable().references('id').inTable('telemetry_exporters');t.text('blob_url').notNullable();t.text('etag');t.text('checked_at').notNullable();t.integer('observations').notNullable();t.primary(['exporter_id','blob_url'])})
 await k.schema.createTable('cloud_network_context',t=>{t.text('connection_id').notNullable().references('id').inTable('azure_connections');t.text('resource_id').notNullable();t.text('kind').notNullable();t.text('snapshot_json').notNullable();t.text('observed_at').notNullable();t.primary(['connection_id','resource_id'])})
}
exports.down=async k=>{await k.schema.dropTable('cloud_network_context');await k.schema.dropTable('vnet_blob_checkpoints')}
