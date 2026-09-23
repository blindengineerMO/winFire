exports.up = async knex => {
  await knex.raw("UPDATE nodes SET firewall_state='unmanaged' WHERE firewall_state='enforcing' AND agent_required=1 AND agent_id IS NULL")
}

exports.down = async () => {}
