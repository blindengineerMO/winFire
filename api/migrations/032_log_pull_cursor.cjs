exports.up=async function(knex){
  await knex.schema.createTable('node_log_cursors',table=>{
    table.string('node_id').primary()
    table.bigInteger('last_record_id').notNullable().defaultTo(0)
    table.timestamp('updated_at').notNullable().defaultTo(knex.fn.now())
  })
}
exports.down=async function(knex){await knex.schema.dropTableIfExists('node_log_cursors')}
