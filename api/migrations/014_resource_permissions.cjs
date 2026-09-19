exports.up = async knex => {
  const roles=[['auditor','Auditor'],['editor','Policy Editor'],['admin','Admin'],['owner','Owner']]
  const permissions=[['portal.read','Read control plane'],['portal.edit','Edit managed resources'],['portal.admin','Administer control plane'],['portal.owner','Manage owners']]
  for(const [id,name] of roles)await knex('roles').insert({id,name}).onConflict('id').ignore()
  for(const [id,description] of permissions)await knex('permissions').insert({id,description}).onConflict('id').ignore()
  const byRole={auditor:['portal.read'],editor:['portal.read','portal.edit'],admin:['portal.read','portal.edit','portal.admin'],owner:permissions.map(([id])=>id)}
  for(const [roleId,ids] of Object.entries(byRole))for(const permissionId of ids)await knex('role_permissions').insert({role_id:roleId,permission_id:permissionId}).onConflict(['role_id','permission_id']).ignore()
  await knex.schema.alterTable('node_groups',table=>{table.text('owner_user_id').references('id').inTable('users').onDelete('SET NULL')})
  await knex.raw("UPDATE node_groups SET owner_user_id=(SELECT actor_user_id FROM audit_log WHERE action='node-group.create' AND entity_id=node_groups.id ORDER BY at LIMIT 1)")
  await knex.schema.createTable('resource_grants',table=>{
    table.text('id').primary()
    table.text('resource_type').notNullable()
    table.text('resource_id').notNullable()
    table.text('grantee_user_id').notNullable().references('id').inTable('users').onDelete('CASCADE')
    table.text('permission').notNullable()
    table.text('created_by').references('id').inTable('users').onDelete('SET NULL')
    table.text('created_at').notNullable().defaultTo(knex.fn.now())
    table.unique(['resource_type','resource_id','grantee_user_id'])
  })
  await knex.raw('CREATE INDEX idx_resource_grants_grantee ON resource_grants(grantee_user_id,resource_type,resource_id)')
}

exports.down = async knex => {
  await knex.raw('DROP INDEX IF EXISTS idx_resource_grants_grantee')
  await knex.schema.dropTable('resource_grants')
  await knex.schema.alterTable('node_groups',table=>table.dropColumn('owner_user_id'))
  await knex('role_permissions').whereIn('permission_id',['portal.read','portal.edit','portal.admin','portal.owner']).del()
  await knex('permissions').whereIn('id',['portal.read','portal.edit','portal.admin','portal.owner']).del()
}
