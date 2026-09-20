exports.up=async knex=>{
  await knex.schema.alterTable('jit_grants',table=>table.text('ports_json'))
}
exports.down=async knex=>{
  await knex.schema.alterTable('jit_grants',table=>table.dropColumn('ports_json'))
}
