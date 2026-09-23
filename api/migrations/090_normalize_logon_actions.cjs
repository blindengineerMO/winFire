exports.up = async knex => {
  await knex.raw("UPDATE log_events SET action='logon' WHERE event_id=4624 AND (action IS NULL OR action<>'logon')")
  await knex.raw("UPDATE log_events SET action='logoff' WHERE event_id=4634 AND (action IS NULL OR action<>'logoff')")
}

exports.down = async () => {}
