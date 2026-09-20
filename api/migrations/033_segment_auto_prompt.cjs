exports.up=async function(knex){await knex.schema.alterTable('identity_segments',table=>table.boolean('auto_prompt_enabled').notNullable().defaultTo(false))}
exports.down=async function(knex){await knex.schema.alterTable('identity_segments',table=>table.dropColumn('auto_prompt_enabled'))}
