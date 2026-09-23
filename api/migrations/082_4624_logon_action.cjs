exports.up = async knex => {
  // Older collectors persisted 4624 as "success". Normalize those rows so
  // existing Access event history uses the same Logon label as new events.
  await knex.raw("UPDATE log_events SET action='logon' WHERE event_id=4624 AND (action='success' OR action IS NULL)")
}

exports.down = async () => {}
