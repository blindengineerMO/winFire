exports.up = async knex => {
  await knex.schema.createTable('directory_connections', table => {
    table.text('id').primary()
    table.text('url')
    table.text('base_dn')
    table.text('bind_credential_id').references('id').inTable('credentials').onDelete('SET NULL')
    table.text('node_credential_id').references('id').inTable('credentials').onDelete('SET NULL')
    table.boolean('enabled').notNullable().defaultTo(false)
    table.integer('sync_interval_minutes').notNullable().defaultTo(60)
    table.text('last_synced_at')
    table.text('last_sync_attempt_at')
    table.text('last_sync_status')
    table.text('last_sync_error')
    table.integer('last_sync_count')
  })
  await knex('directory_connections').insert({id:'default',enabled:false,sync_interval_minutes:60})
  await knex.schema.alterTable('nodes', table => {
    table.text('inventory_source').notNullable().defaultTo('manual')
    table.text('ad_guid')
    table.text('ad_sid')
    table.text('ad_dn')
    table.text('ad_snapshot_json')
    table.text('ad_last_seen_at')
    table.boolean('ad_enabled')
    table.boolean('ad_missing').notNullable().defaultTo(false)
  })
  await knex.raw('CREATE UNIQUE INDEX idx_nodes_ad_guid ON nodes(ad_guid) WHERE ad_guid IS NOT NULL')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_nodes_ad_guid')
  await knex.schema.alterTable('nodes', table => {
    table.dropColumn('ad_missing')
    table.dropColumn('ad_last_seen_at')
    table.dropColumn('ad_enabled')
    table.dropColumn('ad_snapshot_json')
    table.dropColumn('ad_dn')
    table.dropColumn('ad_sid')
    table.dropColumn('ad_guid')
    table.dropColumn('inventory_source')
  })
  await knex.schema.dropTable('directory_connections')
}
