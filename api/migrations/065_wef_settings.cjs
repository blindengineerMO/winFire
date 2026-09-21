exports.up = async knex => {
  const has = await knex('app_settings').whereIn('key', ['wef_enabled', 'wef_path']).select('key')
  const existing = new Set(has.map(row => row.key))
  const rows = []
  if (!existing.has('wef_enabled')) rows.push({key:'wef_enabled',value:'false'})
  if (!existing.has('wef_path')) rows.push({key:'wef_path',value:'/api/v1/wef/wsman'})
  if (rows.length) await knex('app_settings').insert(rows)
}

exports.down = knex => knex('app_settings').whereIn('key', ['wef_enabled', 'wef_path']).del()
