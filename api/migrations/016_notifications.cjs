exports.up=async function up(knex){
  await knex.schema.createTable('notifications',table=>{
    table.string('id').primary()
    table.string('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE')
    table.string('event_key').notNullable()
    table.string('category').notNullable()
    table.string('title').notNullable()
    table.text('body').notNullable()
    table.string('entity_type')
    table.string('entity_id')
    table.timestamp('created_at').notNullable().defaultTo(knex.fn.now())
    table.timestamp('read_at')
    table.unique(['user_id','event_key'])
    table.index(['user_id','created_at'])
  })
  await knex.schema.createTable('notification_deliveries',table=>{
    table.string('id').primary()
    table.string('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE')
    table.string('event_key').notNullable()
    table.string('category').notNullable()
    table.string('channel').notNullable()
    table.string('title').notNullable()
    table.text('body').notNullable()
    table.string('status').notNullable().defaultTo('pending')
    table.integer('attempts').notNullable().defaultTo(0)
    table.timestamp('next_attempt_at').notNullable().defaultTo(knex.fn.now())
    table.timestamp('sent_at')
    table.text('last_error')
    table.unique(['user_id','event_key','channel'])
    table.index(['status','next_attempt_at'])
  })
}

exports.down=async function down(knex){
  await knex.schema.dropTableIfExists('notification_deliveries')
  await knex.schema.dropTableIfExists('notifications')
}
