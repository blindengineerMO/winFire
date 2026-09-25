exports.up=async k=>{
  await k.schema.createTable('user_api_keys',t=>{
    t.text('id').primary();t.text('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE')
    t.text('name').notNullable();t.text('token_hash').notNullable().unique();t.text('prefix').notNullable()
    t.text('scopes_json').notNullable();t.text('reporter_id').references('id').inTable('ai_reporters').onDelete('SET NULL')
    t.text('created_at').notNullable();t.text('updated_at').notNullable();t.text('expires_at').notNullable()
    t.text('last_used_at');t.text('revoked_at');t.index(['user_id','created_at'])
  })
}
exports.down=async k=>k.schema.dropTable('user_api_keys')
