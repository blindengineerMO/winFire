exports.up=async knex=>{
  const table='entra_integrations'
  if(!(await knex.schema.hasColumn(table,'client_auth_method')))await knex.schema.alterTable(table,t=>t.text('client_auth_method').notNullable().defaultTo('secret'))
  if(!(await knex.schema.hasColumn(table,'client_certificate_sealed')))await knex.schema.alterTable(table,t=>t.text('client_certificate_sealed'))
  if(!(await knex.schema.hasColumn(table,'client_private_key_sealed')))await knex.schema.alterTable(table,t=>t.text('client_private_key_sealed'))
}
exports.down=async knex=>{
  const table='entra_integrations'
  if(await knex.schema.hasColumn(table,'client_private_key_sealed'))await knex.schema.alterTable(table,t=>t.dropColumn('client_private_key_sealed'))
  if(await knex.schema.hasColumn(table,'client_certificate_sealed'))await knex.schema.alterTable(table,t=>t.dropColumn('client_certificate_sealed'))
  if(await knex.schema.hasColumn(table,'client_auth_method'))await knex.schema.alterTable(table,t=>t.dropColumn('client_auth_method'))
}
