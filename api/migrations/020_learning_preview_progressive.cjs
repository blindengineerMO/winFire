const {randomUUID}=require('node:crypto')

exports.up = async knex => {
  await knex.schema.alterTable('policies', table => {
    table.text('origin').notNullable().defaultTo('manual')
    table.text('source_node_id')
  })
  await knex.raw(`UPDATE policies SET origin='learned',source_node_id=(SELECT s.node_id FROM learning_sessions s WHERE s.generated_policy_id=policies.id ORDER BY s.started_at DESC,s.rowid DESC LIMIT 1) WHERE id IN (SELECT generated_policy_id FROM learning_sessions WHERE generated_policy_id IS NOT NULL) AND id IN (SELECT generated_policy_id FROM learning_sessions s WHERE s.rowid=(SELECT MAX(s2.rowid) FROM learning_sessions s2 WHERE s2.node_id=s.node_id AND s2.generated_policy_id IS NOT NULL))`)
  await knex.raw("CREATE UNIQUE INDEX idx_personal_learned_policy ON policies(source_node_id) WHERE origin='learned' AND source_node_id IS NOT NULL")
  await knex.schema.alterTable('learning_sessions', table => {
    table.integer('progressive_enabled').notNullable().defaultTo(0)
    table.text('progressive_start_at')
    table.integer('progressive_interval_hours')
    table.text('next_progressive_at')
    table.text('last_progressive_at')
    table.text('current_apply_attempt_id')
  })
  await knex('app_settings').insert([
    {key:'progressive_learning_enabled',value:'false'},
    {key:'progressive_learning_start_days',value:'15'},
    {key:'progressive_learning_interval_hours',value:'24'}
  ])
  // Older installations already have active sessions. Give them the same
  // stable, node-owned draft that newly started sessions receive.
  const pending=await knex('learning_sessions as s').join('nodes as n','n.id','s.node_id')
    .whereNull('s.generated_policy_id').whereIn('s.status',['active','review','apply-failed','applying'])
    .select('s.id','s.node_id','n.hostname')
  for(const session of pending){
    let policy=await knex('policies').where({origin:'learned',source_node_id:session.node_id}).first()
    if(!policy){
      const policyId=randomUUID(),versionId=randomUUID()
      await knex('policies').insert({id:policyId,name:`Learned ${session.hostname}`,description:`Personal learned firewall policy for ${session.hostname}`,current_version_id:versionId,origin:'learned',source_node_id:session.node_id})
      await knex('policy_versions').insert({id:versionId,policy_id:policyId,version_no:1,graph_json:JSON.stringify({nodes:[],edges:[]}),rules_compiled_json:'[]',comment:'Learning started'})
      policy={id:policyId}
    }
    await knex('learning_sessions').where({id:session.id}).update({generated_policy_id:policy.id})
  }
  await knex.raw('CREATE INDEX idx_learning_progressive_due ON learning_sessions(mode,status,next_progressive_at)')
}
exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_learning_progressive_due')
  await knex('app_settings').whereIn('key',['progressive_learning_enabled','progressive_learning_start_days','progressive_learning_interval_hours']).del()
  await knex.schema.alterTable('learning_sessions', table => {
    table.dropColumn('last_progressive_at')
    table.dropColumn('next_progressive_at')
    table.dropColumn('progressive_interval_hours')
    table.dropColumn('progressive_start_at')
    table.dropColumn('progressive_enabled')
    table.dropColumn('current_apply_attempt_id')
  })
  await knex.raw('DROP INDEX IF EXISTS idx_personal_learned_policy')
  await knex.schema.alterTable('policies', table => {
    table.dropColumn('source_node_id')
    table.dropColumn('origin')
  })
}
