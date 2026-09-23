/** Normalize legacy ESXi records to the API management mode. */
exports.up = async knex => {
  await knex.raw(`UPDATE nodes
    SET device_type='esxi',
        management_type='api',
        manageability='unmanaged',
        firewall_state='unmanaged',
        snmp_capable=1,
        agent_required=0
    WHERE lower(coalesce(device_type,''))='esxi'
       OR lower(coalesce(hypervisor,''))='vmware esxi'
       OR lower(coalesce(os_name,''))='vmware esxi'
       OR transport='esxi-soap'`)
}

exports.down = async () => {}
