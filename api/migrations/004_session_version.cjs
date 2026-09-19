exports.up = knex => knex.schema.alterTable('users', table => table.integer('session_version').notNullable().defaultTo(0))
exports.down = knex => knex.schema.alterTable('users', table => table.dropColumn('session_version'))
