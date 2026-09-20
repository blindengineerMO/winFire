exports.up=async knex=>{
  await knex.schema.alterTable('identity_segments',table=>table.text('node_group_id').references('id').inTable('node_groups').onDelete('SET NULL'))
  await knex.raw('CREATE INDEX idx_identity_segment_group ON identity_segments(node_group_id)')
}
exports.down=async knex=>{await knex.schema.alterTable('identity_segments',table=>table.dropColumn('node_group_id'))}
