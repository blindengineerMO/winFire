exports.up = async knex => {
  await knex.schema.createTable('classifier_rules', table => {
    table.text('id').primary()
    table.text('catalog_id')
    table.text('protocol').notNullable()
    table.integer('port_start')
    table.integer('port_end')
    table.text('service').notNullable()
    table.text('description')
    table.text('source').notNullable().defaultTo('custom')
    table.integer('priority').notNullable().defaultTo(10)
    table.integer('enabled').notNullable().defaultTo(1)
    table.text('created_by').references('id').inTable('users').onDelete('SET NULL')
    table.text('updated_by').references('id').inTable('users').onDelete('SET NULL')
    table.text('created_at').notNullable()
    table.text('updated_at').notNullable()
  })
  await knex.raw('CREATE INDEX idx_classifier_rules_match ON classifier_rules(enabled,protocol,port_start,port_end,priority)')
  await knex.raw('CREATE UNIQUE INDEX idx_classifier_rule_catalog ON classifier_rules(catalog_id) WHERE catalog_id IS NOT NULL')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_classifier_rule_catalog')
  await knex.raw('DROP INDEX IF EXISTS idx_classifier_rules_match')
  await knex.schema.dropTableIfExists('classifier_rules')
}
