exports.up = knex => knex.schema.alterTable('verifier_results', table => {
  table.text('vantage_node_id').nullable()
})

exports.down = knex => knex.schema.alterTable('verifier_results', table => {
  table.dropColumn('vantage_node_id')
})
