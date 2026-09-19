exports.up=async function up(knex){
  await knex.schema.alterTable('directory_connections',table=>{
    table.boolean('allow_ldap_fallback').notNullable().defaultTo(false)
    table.text('ldap_fallback_approved_by').references('id').inTable('users').onDelete('SET NULL')
    table.text('ldap_fallback_approved_at')
    table.text('last_transport')
  })
}

exports.down=async function down(knex){
  await knex.schema.alterTable('directory_connections',table=>{
    table.dropColumn('last_transport')
    table.dropColumn('ldap_fallback_approved_at')
    table.dropColumn('ldap_fallback_approved_by')
    table.dropColumn('allow_ldap_fallback')
  })
}
