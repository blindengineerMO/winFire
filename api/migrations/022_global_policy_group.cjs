const GLOBAL_GROUP_ID='winfire-global-all-nodes'

exports.up=async knex=>{
  await knex('node_groups').insert({id:GLOBAL_GROUP_ID,name:'All nodes (global)'})
  await knex.raw('INSERT OR IGNORE INTO node_group_members(group_id,node_id) SELECT ?,id FROM nodes',[GLOBAL_GROUP_ID])
  await knex.raw(`CREATE TRIGGER winfire_global_group_new_node AFTER INSERT ON nodes BEGIN
    INSERT OR IGNORE INTO node_group_members(group_id,node_id) VALUES('${GLOBAL_GROUP_ID}',NEW.id);
  END`)
}

exports.down=async knex=>{
  await knex.raw('DROP TRIGGER IF EXISTS winfire_global_group_new_node')
  await knex('policy_assignments').where({node_group_id:GLOBAL_GROUP_ID}).del()
  await knex('node_group_members').where({group_id:GLOBAL_GROUP_ID}).del()
  await knex('node_groups').where({id:GLOBAL_GROUP_ID}).del()
}
