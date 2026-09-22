exports.up = async knex => {
  await knex.schema.createTable('classifier_process_rules', table => {
    table.text('id').primary()
    table.text('executable_pattern').notNullable()
    table.text('service').notNullable()
    table.text('description')
    table.text('source').notNullable().defaultTo('custom')
    table.integer('priority').notNullable().defaultTo(10)
    table.integer('enabled').notNullable().defaultTo(1)
    table.text('created_by').references('id').inTable('users').onDelete('SET NULL')
    table.text('updated_by').references('id').inTable('users').onDelete('SET NULL')
    table.text('created_at').notNullable()
    table.text('updated_at').notNullable()
  })
  await knex.raw('CREATE INDEX idx_classifier_process_match ON classifier_process_rules(enabled,priority)')
  const timestamp = new Date().toISOString()
  await knex('classifier_process_rules').insert([
    {id:'builtin-process-lsass',executable_pattern:'lsass.exe',service:'Local Security Authority Subsystem Service',description:'Windows security authority process',source:'built-in',priority:10,enabled:1,created_at:timestamp,updated_at:timestamp},
    {id:'builtin-process-dfsrs',executable_pattern:'dfsrs.exe',service:'Distributed File System Replication (DFSR)',description:'Windows Distributed File System Replication service',source:'built-in',priority:10,enabled:1,created_at:timestamp,updated_at:timestamp},
  ])
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_classifier_process_match')
  await knex.schema.dropTableIfExists('classifier_process_rules')
}
