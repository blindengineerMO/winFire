exports.up=async knex=>knex.schema.alterTable('log_events',table=>{
  table.text('filter_origin')
  table.text('filter_runtime_id')
})

exports.down=async knex=>knex.schema.alterTable('log_events',table=>{
  table.dropColumn('filter_origin')
  table.dropColumn('filter_runtime_id')
})
