exports.up=async knex=>{
  await knex.schema.alterTable('snmp_mib_library',t=>{t.text('source_path');t.text('parse_status').notNullable().defaultTo('ready');t.text('parse_error')})
  await knex.schema.createTable('snmp_mib_files',t=>{
    t.text('id').primary();t.text('module_name');t.text('filename').notNullable();t.text('source_path').notNullable();t.text('sha256').notNullable();t.bigInteger('size').notNullable();t.text('origin').notNullable();t.text('source_url');t.text('revision');t.text('status').notNullable();t.text('error');t.text('created_at').notNullable();t.unique(['origin','filename']);t.index(['module_name']);t.index(['status'])
  })
}
exports.down=async knex=>{await knex.schema.dropTableIfExists('snmp_mib_files');await knex.schema.alterTable('snmp_mib_library',t=>{t.dropColumn('source_path');t.dropColumn('parse_status');t.dropColumn('parse_error')})}
