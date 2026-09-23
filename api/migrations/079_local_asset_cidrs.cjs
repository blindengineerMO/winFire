exports.up = async knex => {
  await knex('app_settings').insert({key: 'local_asset_cidrs', value: '[]'}).onConflict('key').ignore()
}

exports.down = knex => knex('app_settings').where({key: 'local_asset_cidrs'}).del()

