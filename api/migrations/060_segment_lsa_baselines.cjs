exports.up=async knex=>{
  await knex.schema.createTable('segment_lsa_baselines',table=>{
    table.text('segment_id').notNullable().references('id').inTable('identity_segments').onDelete('CASCADE')
    table.text('node_id').notNullable().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('account_sid').notNullable()
    table.text('allow_right').notNullable()
    table.text('deny_right').notNullable()
    table.boolean('allow_was_present').notNullable()
    table.boolean('deny_was_present').notNullable()
    table.text('enforced_at').notNullable()
    table.text('enforced_by').references('id').inTable('users').onDelete('SET NULL')
    table.primary(['segment_id','node_id'])
  })
  await knex.raw('CREATE INDEX idx_segment_lsa_node ON segment_lsa_baselines(node_id,account_sid)')
}

exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_segment_lsa_node')
  await knex.schema.dropTableIfExists('segment_lsa_baselines')
}
