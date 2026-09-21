exports.up=async knex=>{
  const memberHas=await knex.schema.hasColumn('entra_group_members','settings_key')
  if(!memberHas)await knex.schema.alterTable('entra_group_members',table=>table.text('settings_key'))
  const syncHas=await knex.schema.hasColumn('entra_group_sync','settings_key')
  if(!syncHas)await knex.schema.alterTable('entra_group_sync',table=>table.text('settings_key'))
}
exports.down=async knex=>{
  if(await knex.schema.hasColumn('entra_group_members','settings_key'))await knex.schema.alterTable('entra_group_members',table=>table.dropColumn('settings_key'))
  if(await knex.schema.hasColumn('entra_group_sync','settings_key'))await knex.schema.alterTable('entra_group_sync',table=>table.dropColumn('settings_key'))
}
