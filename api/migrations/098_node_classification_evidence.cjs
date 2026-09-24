/** Persist the signal that caused a discovery or SNMP device classification. */
exports.up = async knex => {
  if (!(await knex.schema.hasColumn('nodes', 'vendor'))) {
    await knex.schema.alterTable('nodes', table => table.text('vendor'))
  }
  if (!(await knex.schema.hasColumn('nodes', 'classification_evidence_json'))) {
    await knex.schema.alterTable('nodes', table => table.text('classification_evidence_json'))
  }

  // Preserve evidence already captured in node facts by earlier discovery
  // versions while making it queryable with the node record.
  const rows = await knex('node_facts').select('node_id', 'snapshot_json')
  for (const row of rows) {
    let snapshot
    try { snapshot = JSON.parse(row.snapshot_json || '{}') || {} } catch { snapshot = {} }
    const classification = snapshot.classification || {}
    const hypervisor = snapshot.hypervisor || {}
    const vendor = classification.vendor || hypervisor.vendor || hypervisor.hypervisor || null
    const legacyEvidence = classification.classificationEvidence || classification.evidence || hypervisor.classificationEvidence || hypervisor.evidence || null
    const identity = snapshot.identity || {}
    const evidence = legacyEvidence || (vendor ? {
      source: snapshot.source === 'snmp' ? 'snmp' : 'legacy-discovery',
      method: snapshot.source === 'snmp' ? 'identity' : 'discovery-record',
      matched: vendor,
      matchedOid: identity.sysObjectId || null,
      signal: identity.sysObjectId ? 'sysObjectID' : 'persisted classification',
      confidence: 'inferred'
    } : null)
    if (vendor || evidence) {
      await knex('nodes').where({id: row.node_id}).update({
        ...(vendor ? {vendor} : {}),
        ...(evidence ? {classification_evidence_json: typeof evidence === 'string' ? JSON.stringify({source: 'legacy-discovery', signal: evidence}) : JSON.stringify(evidence)} : {})
      })
    }
  }
}

exports.down = async knex => {
  for (const name of ['classification_evidence_json', 'vendor']) {
    if (await knex.schema.hasColumn('nodes', name)) await knex.schema.alterTable('nodes', table => table.dropColumn(name))
  }
}
