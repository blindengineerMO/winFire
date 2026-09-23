/** Backfill OS family labels already observed by the ICMP discovery probe. */
exports.up = async knex => {
  await knex.raw(`UPDATE nodes SET discovery_os_family=CASE
    WHEN discovery_ttl BETWEEN 1 AND 64 THEN 'linux-unix'
    WHEN discovery_ttl BETWEEN 65 AND 128 THEN 'windows'
    WHEN discovery_ttl BETWEEN 129 AND 255 THEN 'network-device'
    ELSE discovery_os_family END
  WHERE discovery_os_family IS NULL AND discovery_ttl IS NOT NULL`)
  await knex.raw(`UPDATE nodes SET os_name=CASE
    WHEN lower(coalesce(discovery_os_family,'')) IN ('linux','linux-unix','unix') THEN 'Linux / Unix'
    WHEN lower(coalesce(discovery_os_family,''))='windows' THEN 'Windows'
    WHEN lower(coalesce(discovery_os_family,''))='network-device' THEN 'Network device'
    ELSE os_name END,
    platform=CASE
    WHEN lower(coalesce(discovery_os_family,'')) IN ('linux','linux-unix','unix') AND (platform IS NULL OR lower(platform) IN ('','unknown','unidentified','unknown os')) THEN 'Linux / Unix'
    WHEN lower(coalesce(discovery_os_family,''))='windows' AND (platform IS NULL OR lower(platform) IN ('','unknown','unidentified','unknown os')) THEN 'Windows'
    WHEN lower(coalesce(discovery_os_family,''))='network-device' AND (platform IS NULL OR lower(platform) IN ('','unknown','unidentified','unknown os')) THEN 'Network device'
    ELSE platform END
  WHERE (os_name IS NULL OR lower(os_name) IN ('','unknown','unidentified','unknown os')) AND discovery_os_family IS NOT NULL`)
}

exports.down = async () => {}
