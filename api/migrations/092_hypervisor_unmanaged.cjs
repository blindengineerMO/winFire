/** Keep previously discovered hypervisors out of managed Windows workflows. */
exports.up = async knex => {
  await knex('nodes')
    .where(builder => builder.whereNotNull('hypervisor').orWhereRaw("lower(coalesce(os_name,'')) like '%esxi%'")
      .orWhereRaw("lower(coalesce(os_name,'')) like '%proxmox%'")
      .orWhereRaw("lower(coalesce(os_name,'')) like '%xenserver%'")
      .orWhereRaw("lower(coalesce(os_name,'')) like '%azure local%'")
      .orWhereRaw("lower(coalesce(os_name,'')) like '%citrix hypervisor%'")
      .orWhereRaw("lower(coalesce(manageability,'')) in ('unmanageable','hypervisor')")
    )
    .update({manageability:'unmanaged', agent_required:0, firewall_state:'unmanaged', snmp_capable:1})
}

exports.down = async () => {}
