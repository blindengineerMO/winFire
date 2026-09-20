exports.up=async function(knex){
  await knex.schema.alterTable('jit_grants',table=>table.string('prompt_id'))
  await knex.schema.alterTable('mfa_entra_flows',table=>table.string('prompt_id'))
}
exports.down=async function(knex){
  await knex.schema.alterTable('mfa_entra_flows',table=>table.dropColumn('prompt_id'))
  await knex.schema.alterTable('jit_grants',table=>table.dropColumn('prompt_id'))
}
