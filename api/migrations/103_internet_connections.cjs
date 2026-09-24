exports.up=async knex=>{
  await knex.schema.createTable('network_boundaries',t=>{t.increments('revision');t.text('cidrs_json').notNullable();t.text('created_at').notNullable()})
  await knex.schema.createTable('internet_index_state',t=>{t.integer('id').primary();t.integer('active_revision');t.integer('desired_revision');t.bigInteger('cursor').notNullable().defaultTo(0);t.bigInteger('high_water').notNullable().defaultTo(0);t.text('updated_at')})
  await knex('internet_index_state').insert({id:1})
  await knex.schema.createTable('internet_event_queue',t=>{t.text('event_id').primary().references('id').inTable('log_events').onDelete('CASCADE')})
  await knex.schema.createTable('internet_peers',t=>{
    t.text('id').primary();t.text('ip').notNullable();t.text('resolver_context').notNullable();t.text('first_seen_at').notNullable();t.text('last_seen_at').notNullable();t.text('names_json').notNullable().defaultTo('[]');t.text('status').notNullable().defaultTo('pending');t.text('checked_at');t.text('last_success_at');t.text('next_lookup_at');t.text('lease_until');t.integer('attempts').notNullable().defaultTo(0);t.text('error');t.unique(['ip','resolver_context']);t.index(['next_lookup_at','lease_until'])
  })
  await knex.schema.createTable('internet_peer_dns_history',t=>{t.increments('id');t.text('peer_id').notNullable().references('id').inTable('internet_peers').onDelete('CASCADE');t.text('checked_at').notNullable();t.text('names_json').notNullable();t.text('status').notNullable();t.text('error');t.index(['peer_id','checked_at'])})
  await knex.schema.createTable('internet_connections',t=>{
    t.text('event_id').notNullable().references('id').inTable('log_events').onDelete('CASCADE');t.integer('revision').notNullable();t.primary(['revision','event_id']);t.integer('original_revision').notNullable();t.text('original_scope').notNullable();t.text('node_id');t.text('observed_at').notNullable();t.text('source_ip');t.text('destination_ip');t.integer('source_port');t.integer('destination_port');t.text('local_ip');t.text('peer_ip');t.text('peer_id').references('id').inTable('internet_peers').onDelete('SET NULL');t.text('direction').notNullable();t.text('attribution').notNullable();t.text('action');t.text('protocol');t.text('program');t.text('category');t.integer('outside').notNullable();
    for(const column of ['observed_at','node_id','peer_ip','peer_id','action','direction'])t.index(['revision',column]);t.index(['event_id'])
  })
  // Most retained observations are local; keep outside-only reads off that history.
  await knex.raw('CREATE INDEX idx_internet_outside_time ON internet_connections(revision,observed_at) WHERE outside=1')
  await knex.raw('CREATE INDEX idx_internet_outside_direction_time ON internet_connections(revision,direction,observed_at) WHERE outside=1')
  await knex.raw(`CREATE TRIGGER internet_event_insert AFTER INSERT ON log_events BEGIN INSERT OR IGNORE INTO internet_event_queue(event_id) VALUES(NEW.id); END`)
  await knex.raw(`CREATE TRIGGER internet_event_update AFTER UPDATE ON log_events BEGIN INSERT OR IGNORE INTO internet_event_queue(event_id) VALUES(NEW.id); END`)
}
exports.down=async knex=>{
  await knex.raw('DROP TRIGGER IF EXISTS internet_event_insert');await knex.raw('DROP TRIGGER IF EXISTS internet_event_update')
  for(const name of ['internet_connections','internet_peer_dns_history','internet_peers','internet_event_queue','internet_index_state','network_boundaries'])await knex.schema.dropTableIfExists(name)
}
