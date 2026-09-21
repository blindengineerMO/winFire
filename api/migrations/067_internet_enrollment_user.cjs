exports.up=async knex=>{
  const tokenHas=await knex.schema.hasColumn('internet_enrollment_tokens','user_id')
  if(!tokenHas)await knex.schema.alterTable('internet_enrollment_tokens',table=>table.text('user_id').references('id').inTable('users').onDelete('SET NULL'))
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_internet_enrollment_user ON internet_enrollment_tokens(user_id,used_at)')
  await knex.raw('CREATE INDEX IF NOT EXISTS idx_internet_devices_user ON internet_extension_devices(user_id,last_seen_at)')
}

exports.down=async knex=>{
  await knex.raw('DROP INDEX IF EXISTS idx_internet_devices_user')
  await knex.raw('DROP INDEX IF EXISTS idx_internet_enrollment_user')
  const has=await knex.schema.hasColumn('internet_enrollment_tokens','user_id')
  if(has)await knex.schema.alterTable('internet_enrollment_tokens',table=>table.dropColumn('user_id'))
}
