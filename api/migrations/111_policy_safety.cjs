exports.up=async k=>{
  await k.schema.alterTable('policy_simulations',t=>{t.text('last_processed_at');t.text('evidence_hash')})
  await k.schema.createTable('policy_simulation_inputs',t=>{
    t.text('simulation_id').notNullable().references('id').inTable('policy_simulations').onDelete('CASCADE')
    t.bigInteger('sequence').notNullable();t.text('event_json').notNullable();t.primary(['simulation_id','sequence'])
  })
  // Old unfinished jobs did not pin their evidence. Never resume them with different input.
  await k('policy_simulations').whereIn('status',['queued','running','observing']).update({status:'cancelled',error:'Evidence snapshot format changed; start a new simulation',finished_at:new Date().toISOString()})
}
exports.down=async k=>{await k.schema.dropTable('policy_simulation_inputs');await k.schema.alterTable('policy_simulations',t=>{t.dropColumn('last_processed_at');t.dropColumn('evidence_hash')})}
