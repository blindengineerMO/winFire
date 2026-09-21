exports.up=async knex=>{
  await knex.raw("CREATE INDEX IF NOT EXISTS idx_learning_events_node_action_time ON log_events(node_id,action,datetime(COALESCE(event_time,received_at)))")
}
exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_learning_events_node_action_time')
}
