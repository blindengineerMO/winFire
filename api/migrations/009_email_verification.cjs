exports.up = knex => knex.schema.createTable('email_verifications', table => {
  table.text('id').primary()
  table.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE')
  table.text('new_email').notNullable()
  table.text('token_hash').notNullable().unique()
  table.text('expires_at').notNullable()
  table.text('used_at')
  table.text('created_at').defaultTo(knex.fn.now())
})

exports.down = knex => knex.schema.dropTable('email_verifications')
