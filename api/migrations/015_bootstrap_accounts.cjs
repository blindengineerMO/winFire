exports.up = async knex => {
  await knex.schema.createTable('bootstrap_accounts',table=>{
    table.text('kind').primary()
    table.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE')
  })
}

exports.down = async knex => knex.schema.dropTable('bootstrap_accounts')
