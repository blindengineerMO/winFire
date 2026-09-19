exports.up = async knex => {
  await knex.schema.alterTable('verifier_results', table => {
    table.text('status').defaultTo('inconclusive')
    table.text('reason')
    table.text('probe_status')
    table.integer('managed_rule_present')
  })
  // Older TCP-only deny checks cannot establish which firewall blocked traffic.
  await knex('verifier_results').update({passed:null,status:'inconclusive',reason:'Legacy result lacked managed-rule evidence'})
}

exports.down = async knex => {
  await knex.schema.alterTable('verifier_results', table => {
    table.dropColumn('status')
    table.dropColumn('reason')
    table.dropColumn('probe_status')
    table.dropColumn('managed_rule_present')
  })
}
