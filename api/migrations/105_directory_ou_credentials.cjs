exports.up=async knex=>{
  await knex.schema.createTable('directory_ou_credentials',t=>{
    t.text('ou_key').primary()
    t.text('ou_dn').notNullable()
    t.text('credential_id').notNullable().references('id').inTable('credentials').onDelete('CASCADE')
  })
  // Existing bindings have no provenance: preserve them as explicit assignments.
  await knex.schema.alterTable('credential_assignments',t=>{
    t.text('source').notNullable().defaultTo('manual')
    t.text('source_dn')
  })
}
exports.down=async knex=>{
  await knex.schema.dropTable('directory_ou_credentials')
  await knex.schema.alterTable('credential_assignments',t=>{t.dropColumn('source_dn');t.dropColumn('source')})
}
