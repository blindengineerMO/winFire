/** Persist bounded device-type hints inferred from passive traffic. */
exports.up = async knex => {
  for (const [table, columns] of [
    ['nodes', ['passive_device_hint', 'passive_device_hint_json']],
    ['passive_discovery_candidates', ['device_type_hint', 'device_type_hint_json']]
  ]) {
    for (const name of columns) {
      if (!(await knex.schema.hasColumn(table, name))) {
        await knex.schema.alterTable(table, schema => schema.text(name))
      }
    }
  }
}

exports.down = async knex => {
  for (const [table, columns] of [
    ['passive_discovery_candidates', ['device_type_hint_json', 'device_type_hint']],
    ['nodes', ['passive_device_hint_json', 'passive_device_hint']]
  ]) {
    for (const name of columns) {
      if (await knex.schema.hasColumn(table, name)) await knex.schema.alterTable(table, schema => schema.dropColumn(name))
    }
  }
}
