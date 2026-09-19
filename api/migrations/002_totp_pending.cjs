exports.up = knex => knex.schema.alterTable('users', table => table.text('totp_pending'))
exports.down = knex => knex.schema.alterTable('users', table => table.dropColumn('totp_pending'))
