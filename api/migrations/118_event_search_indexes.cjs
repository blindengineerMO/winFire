exports.up=async knex=>{
  // Match the search expression exactly, including mixed ISO/SQLite timestamps.
  await knex.raw('CREATE INDEX idx_logs_search_time ON log_events(COALESCE(julianday(COALESCE(event_time,received_at)),0),id)')
  await knex.raw('CREATE INDEX idx_logs_search_node_time ON log_events(node_id,COALESCE(julianday(COALESCE(event_time,received_at)),0),id)')
  await knex.raw('CREATE INDEX idx_logs_search_action_time ON log_events(action,COALESCE(julianday(COALESCE(event_time,received_at)),0),id)')
  await knex.raw('CREATE INDEX idx_logs_search_event_time ON log_events(event_id,COALESCE(julianday(COALESCE(event_time,received_at)),0),id)')
}

exports.down=async knex=>{
  for(const name of ['idx_logs_search_time','idx_logs_search_node_time','idx_logs_search_action_time','idx_logs_search_event_time'])await knex.raw(`DROP INDEX IF EXISTS ${name}`)
}
