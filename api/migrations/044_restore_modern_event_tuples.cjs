exports.up=async knex=>{
  // Modern Windows WFP events use SourceAddress/SourcePort for the remote
  // client on inbound traffic. Older builds used those fields for the local
  // listener. Repair only rows whose stored source is a known local address.
  await knex.raw(`UPDATE log_events AS e
    SET src_ip=e.dst_ip,src_port=e.dst_port,dst_ip=e.src_ip,dst_port=e.src_port
    WHERE e.pattern_id IS NULL AND e.event_type='firewall' AND e.direction='in'
      AND e.src_ip IS NOT NULL AND e.dst_ip IS NOT NULL AND e.src_ip<>e.dst_ip
      AND EXISTS (
        SELECT 1 FROM node_facts AS f,
          json_each(f.snapshot_json,'$.network') AS adapter,
          json_each(adapter.value,'$.ipAddresses') AS address
        WHERE f.node_id=e.node_id AND address.value=e.src_ip
      )`)
}

// Historical WFP field order is unavailable for an automatic reverse repair.
exports.down=async()=>{}
