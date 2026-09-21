exports.up=async knex=>{
  await knex.schema.createTable('traffic_ignore_rules',table=>{
    table.text('id').primary()
    table.text('label').notNullable()
    table.integer('event_id').notNullable()
    table.text('action')
    table.text('protocol')
    table.text('src_ip')
    table.text('dst_ip')
    table.integer('dst_port')
    table.text('direction')
    table.text('program')
    table.text('account_sid')
    table.text('fingerprint').notNullable().unique()
    table.text('created_by').references('users.id')
    table.text('created_at').notNullable().defaultTo(knex.fn.now())
  })
  await knex.raw('CREATE INDEX idx_traffic_ignore_event ON traffic_ignore_rules(event_id)')
}

exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_traffic_ignore_event')
  await knex.schema.dropTableIfExists('traffic_ignore_rules')
}
