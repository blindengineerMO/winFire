exports.up=async knex=>{
  await knex.schema.createTable('node_loopback_baseline',table=>{
    table.text('node_id').primary().references('id').inTable('nodes').onDelete('CASCADE')
    table.text('status').notNullable().defaultTo('pending')
    table.text('last_attempt_at')
    table.text('applied_at')
    table.text('last_error')
    table.text('job_id')
  })
}
exports.down=async knex=>{await knex.schema.dropTableIfExists('node_loopback_baseline')}
