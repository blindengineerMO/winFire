exports.up=async knex=>{
  await knex.schema.alterTable('log_events',table=>table.integer('process_id'))
}
exports.down=async knex=>{
  await knex.schema.alterTable('log_events',table=>table.dropColumn('process_id'))
}
