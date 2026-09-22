exports.up = async knex => {
  const columns = [
    ['traffic_class', table => table.text('traffic_class').notNullable().defaultTo('unicast')],
    ['traffic_scope', table => table.text('traffic_scope').notNullable().defaultTo('unknown')],
    ['traffic_service', table => table.text('traffic_service')],
    ['classification_reason', table => table.text('classification_reason')],
    ['classification_json', table => table.text('classification_json')]
  ]
  for (const [name, add] of columns) {
    if (!(await knex.schema.hasColumn('network_map_pairs', name))) await knex.schema.alterTable('network_map_pairs', add)
  }
  await knex('network_map_pairs').update({
    traffic_class: knex.raw("CASE WHEN external=1 THEN 'public-unicast' ELSE 'unicast' END"),
    traffic_scope: knex.raw("CASE WHEN external=1 THEN 'external' ELSE 'internal' END"),
    classification_reason: knex.raw("CASE WHEN external=1 THEN 'Imported mapping row; rebuild the map to analyze its address scope' ELSE 'Imported mapping row; rebuild the map to identify its traffic type' END")
  })
}

exports.down = async knex => {
  for (const name of ['classification_json', 'classification_reason', 'traffic_service', 'traffic_scope', 'traffic_class']) {
    if (await knex.schema.hasColumn('network_map_pairs', name)) await knex.schema.alterTable('network_map_pairs', table => table.dropColumn(name))
  }
}
