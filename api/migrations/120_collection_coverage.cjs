exports.up=async k=>{
  await k.schema.createTable('collection_coverage_windows',t=>{
    t.text('id').primary();t.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    t.text('source').notNullable();t.text('started_at').notNullable();t.text('ended_at').notNullable();t.integer('reports').notNullable()
    t.boolean('closed').notNullable().defaultTo(false);t.index(['node_id','started_at','ended_at'])
  })
}
exports.down=async k=>k.schema.dropTable('collection_coverage_windows')
