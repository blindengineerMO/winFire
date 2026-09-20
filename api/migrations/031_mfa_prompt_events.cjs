exports.up=async function(knex){
  await knex.schema.createTable('mfa_prompt_events',table=>{
    table.string('id').primary()
    table.string('segment_id').notNullable()
    table.string('target_node_id').notNullable()
    table.string('source_node_id')
    table.string('log_event_id').notNullable()
    table.string('source_ip')
    table.string('status').notNullable().defaultTo('pending')
    table.string('opened_user')
    table.integer('opened_session_id')
    table.string('error')
    table.timestamp('created_at').notNullable().defaultTo(knex.fn.now())
    table.timestamp('expires_at').notNullable()
    table.timestamp('opened_at')
    table.timestamp('consumed_at')
    table.unique(['segment_id','log_event_id'])
    table.index(['status','created_at'])
    table.index(['segment_id','source_ip','created_at'])
  })
}
exports.down=async function(knex){await knex.schema.dropTableIfExists('mfa_prompt_events')}
