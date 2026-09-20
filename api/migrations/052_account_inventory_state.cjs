exports.up=knex=>knex.schema.createTable('account_inventory_state',table=>{
  table.text('node_id').primary().references('id').inTable('nodes').onDelete('CASCADE')
  table.text('collected_at').notNullable()
})
exports.down=knex=>knex.schema.dropTableIfExists('account_inventory_state')
