exports.up=async function up(knex){
  await knex.schema.alterTable('policy_assignments',table=>{
    table.text('removal_job_id')
  })
}

exports.down=async function down(knex){
  await knex.schema.alterTable('policy_assignments',table=>{
    table.dropColumn('removal_job_id')
  })
}
