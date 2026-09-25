exports.up=async k=>{
  await k.schema.createTable('node_capability_evidence',t=>{t.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE');t.text('capability').notNullable();t.text('source').notNullable();t.text('last_success_at');t.text('last_failure_at');t.text('failure_code');t.text('detail_json').notNullable().defaultTo('{}');t.primary(['node_id','capability','source'])})
}
exports.down=async k=>k.schema.dropTable('node_capability_evidence')
