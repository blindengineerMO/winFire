exports.up=async function(knex){
  const has=await knex.schema.hasColumn('identity_segments','entra_group_id')
  if(!has)await knex.schema.alterTable('identity_segments',table=>table.text('entra_group_id'))
}
exports.down=async function(knex){
  const has=await knex.schema.hasColumn('identity_segments','entra_group_id')
  if(has)await knex.schema.alterTable('identity_segments',table=>table.dropColumn('entra_group_id'))
}
