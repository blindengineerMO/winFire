exports.up = knex => knex.schema.createTable('policy_drift_checks', table => {
  table.text('id').primary()
  table.text('policy_id').notNullable().references('id').inTable('policies').onDelete('CASCADE')
  table.text('version_id').notNullable().references('id').inTable('policy_versions').onDelete('CASCADE')
  table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
  table.text('status').notNullable()
  table.text('diff_json')
  table.text('error')
  table.text('checked_at').defaultTo(knex.fn.now())
  table.index(['node_id','policy_id','checked_at'])
})

exports.down = knex => knex.schema.dropTable('policy_drift_checks')
