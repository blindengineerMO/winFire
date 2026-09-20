exports.up=async knex=>{
  await knex.schema.createTable('entra_integrations',table=>{
    table.text('id').primary()
    table.text('tenant_id').notNullable()
    table.text('client_id').notNullable()
    table.text('client_secret_sealed')
    table.boolean('enabled').notNullable().defaultTo(false)
    table.text('updated_at').notNullable()
    table.text('updated_by')
  })
}
exports.down=async knex=>{await knex.schema.dropTableIfExists('entra_integrations')}
