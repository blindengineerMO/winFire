exports.up = async knex => {
  await knex.schema.createTable('passive_discovery_candidates', table => {
    table.text('id').primary()
    table.text('ip').notNullable().unique()
    table.text('mac')
    table.text('source_node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('hostname')
    table.text('first_seen_at').notNullable()
    table.text('last_seen_at').notNullable()
    table.text('status').notNullable().defaultTo('queued')
    table.integer('attempts').notNullable().defaultTo(0)
    table.text('next_attempt_at')
    table.text('node_id').references('id').inTable('nodes').onDelete('SET NULL')
    table.text('last_error')
    table.text('updated_at').notNullable()
  })
  await knex.raw('CREATE INDEX idx_passive_discovery_due ON passive_discovery_candidates(status,next_attempt_at,last_seen_at)')
  await knex.raw('CREATE INDEX idx_passive_discovery_source ON passive_discovery_candidates(source_node_id,last_seen_at)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_passive_discovery_source')
  await knex.raw('DROP INDEX IF EXISTS idx_passive_discovery_due')
  await knex.schema.dropTableIfExists('passive_discovery_candidates')
}
