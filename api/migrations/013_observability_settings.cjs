exports.up = async knex => {
  await knex('app_settings').insert([
    {key:'log_retention_days',value:'90'},
    {key:'dns_refresh_hours',value:'24'}
  ])
  await knex.raw('CREATE INDEX idx_dns_lookups_checked ON dns_lookups(checked_at)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_dns_lookups_checked')
  await knex('app_settings').whereIn('key',['log_retention_days','dns_refresh_hours']).del()
}
