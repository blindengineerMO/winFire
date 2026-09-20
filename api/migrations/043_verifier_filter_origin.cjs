exports.up=async knex=>knex.schema.alterTable('verifier_results',table=>{
  table.text('firewall_event_filter_origin')
})

exports.down=async knex=>knex.schema.alterTable('verifier_results',table=>{
  table.dropColumn('firewall_event_filter_origin')
})
