exports.up=async function up(knex){
  await knex.schema.alterTable('notification_deliveries',table=>table.string('recipient_email'))
}

exports.down=async function down(knex){
  await knex.schema.alterTable('notification_deliveries',table=>table.dropColumn('recipient_email'))
}
