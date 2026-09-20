exports.up=async knex=>{
  await knex.schema.alterTable('nodes',table=>{
    table.text('probe_status')
    table.text('last_probe_at')
  })
  await knex.raw("UPDATE nodes SET probe_status='rpc-authenticated',last_probe_at=last_seen_at,status='reachable' WHERE status='rpc-authenticated'")
  await knex.raw("UPDATE nodes SET probe_status='port-open',last_probe_at=last_seen_at WHERE status='port-open'")
  await knex.raw("UPDATE nodes SET probe_status='rpc-unverified',last_probe_at=last_seen_at WHERE status='unverified' AND transport='wmi'")
}

exports.down=async knex=>{
  await knex.schema.alterTable('nodes',table=>{
    table.dropColumn('last_probe_at')
    table.dropColumn('probe_status')
  })
}
