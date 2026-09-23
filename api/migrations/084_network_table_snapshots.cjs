exports.up = async knex => {
  if (await knex.schema.hasTable('network_table_snapshots')) return
  await knex.schema.createTable('network_table_snapshots', table => {
    table.text('node_id').primary().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('arp_json').notNullable().defaultTo('[]')
    table.text('state_json').notNullable().defaultTo('[]')
    table.text('source').notNullable().defaultTo('snmp')
    table.text('collected_at').notNullable()
  })
}

exports.down = async knex => { await knex.schema.dropTableIfExists('network_table_snapshots') }
