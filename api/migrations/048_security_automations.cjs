exports.up=async knex=>{
  await knex.schema.createTable('security_automations',table=>{
    table.text('id').primary()
    table.text('name').notNullable()
    table.text('trigger_type').notNullable()
    table.text('destination')
    table.integer('failure_count').notNullable().defaultTo(3)
    table.integer('window_minutes').notNullable().defaultTo(15)
    table.integer('cooldown_minutes').notNullable().defaultTo(60)
    table.text('action_type').notNullable().defaultTo('alert')
    table.integer('disable_minutes').notNullable().defaultTo(60)
    table.boolean('enabled').notNullable().defaultTo(false)
    table.text('created_by').references('id').inTable('users')
    table.text('created_at').notNullable()
    table.text('updated_at').notNullable()
  })
  await knex.schema.createTable('security_automation_incidents',table=>{
    table.text('id').primary()
    table.text('policy_id').notNullable().references('id').inTable('security_automations').onDelete('CASCADE')
    table.text('subject_key').notNullable()
    table.text('event_ref').notNullable()
    table.text('status').notNullable()
    table.text('detail_json')
    table.text('created_at').notNullable()
  })
  await knex.raw('CREATE UNIQUE INDEX idx_security_incident_event ON security_automation_incidents(policy_id,event_ref)')
  await knex.raw('CREATE INDEX idx_security_incident_cooldown ON security_automation_incidents(policy_id,subject_key,created_at)')
}
exports.down=async knex=>{
  await knex.schema.dropTableIfExists('security_automation_incidents')
  await knex.schema.dropTableIfExists('security_automations')
}
