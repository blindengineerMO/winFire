exports.up=async knex=>{
  await knex('app_settings').insert([
    {key:'mfa_prompt_failure_mode',value:'closed'},
    {key:'mfa_prompt_fail_open_minutes',value:'5'}
  ])
  await knex.schema.alterTable('mfa_prompt_events',table=>{
    table.integer('opened_process_id')
    table.bigInteger('source_event_record_id')
  })
  await knex.schema.alterTable('jit_grants',table=>table.text('fallback_reason'))
}
exports.down=async knex=>{
  await knex.schema.alterTable('jit_grants',table=>table.dropColumn('fallback_reason'))
  await knex.schema.alterTable('mfa_prompt_events',table=>{
    table.dropColumn('opened_process_id')
    table.dropColumn('source_event_record_id')
  })
  await knex('app_settings').whereIn('key',['mfa_prompt_failure_mode','mfa_prompt_fail_open_minutes']).del()
}
