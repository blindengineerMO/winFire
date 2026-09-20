exports.up=async knex=>{await knex('app_settings').insert({key:'event_compact_last_at',value:''})}
exports.down=async knex=>{await knex('app_settings').where({key:'event_compact_last_at'}).del()}
