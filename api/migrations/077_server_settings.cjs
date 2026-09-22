exports.up = async knex => {
  const existing = new Set((await knex('app_settings').whereIn('key', [
    'server_fqdn',
    'server_public_base_url',
    'wef_shared_secret_sealed'
  ]).select('key')).map(row => row.key))
  const rows = []
  if (!existing.has('server_fqdn')) rows.push({key: 'server_fqdn', value: ''})
  if (!existing.has('server_public_base_url')) rows.push({key: 'server_public_base_url', value: ''})
  if (!existing.has('wef_shared_secret_sealed')) rows.push({key: 'wef_shared_secret_sealed', value: ''})
  if (rows.length) await knex('app_settings').insert(rows)
}

exports.down = knex => knex('app_settings').whereIn('key', [
  'server_fqdn',
  'server_public_base_url',
  'wef_shared_secret_sealed'
]).del()
