exports.up = async knex => {
  await knex.schema.createTable('snmp_mib_library', t => {
    t.text('id').primary()
    t.text('module_name').notNullable().unique()
    t.text('source').notNullable()
    t.text('filename')
    t.text('content')
    t.text('sha256')
    t.text('metadata_json').notNullable()
    t.text('config_json').notNullable()
    t.boolean('enabled').notNullable().defaultTo(true)
    t.text('created_at').notNullable()
    t.text('updated_at').notNullable()
  })
  await knex.schema.createTable('node_snmp_mibs', t => {
    t.text('node_id').notNullable().references('nodes.id').onDelete('CASCADE')
    t.text('mib_id').notNullable().references('snmp_mib_library.id').onDelete('CASCADE')
    t.text('identity_key').notNullable()
    t.text('evidence_json').notNullable()
    t.text('status').notNullable()
    t.text('last_polled_at').notNullable()
    t.primary(['node_id','mib_id'])
  })
}
exports.down = async knex => {
  await knex.schema.dropTableIfExists('node_snmp_mibs')
  await knex.schema.dropTableIfExists('snmp_mib_library')
}
