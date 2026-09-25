# Azure and Azure Arc discovery

## Scope and capabilities

Administration → Discovery → **Azure / Arc** imports Azure VM configuration and already-onboarded Arc machines. The connector performs ARM list/get reads only. It never creates Azure resources, installs extensions, enables paid logging, writes NSGs, runs commands, or enrolls Arc agents.

| Source | Collected | Unavailable / separate capability |
| --- | --- | --- |
| Microsoft.Compute/virtualMachines | Resource ID, VM UUID, configured hostname, OS family, VM size, tags, location, NIC references | Guest version is unknown unless another source reports it; configuration is not proof of power/reachability |
| Microsoft.Network/networkInterfaces | All returned private IPv4/IPv6 addresses, MACs, subnet/VNet references, public IP references | Public IP resource references are not guessed into addresses |
| Microsoft.HybridCompute/machines | Reported OS/version, machine FQDN, VM UUID, interfaces, hardware properties and Arc status | Connected means Arc connected, not WinFire management verified |

Source observations retain separate fetched and provider-observed timestamps, field provenance and history. Strong identity matches reuse the node ID; IP/name-only and clone/move ambiguity require review. Manual unlink pauses automatic linking. Source disappearance never deletes node policy, group or credential references. Retirement needs three complete misses spanning seven days plus a provider 404. Partial permissions and incomplete enumeration cannot retire records.

## Prerequisites and permissions

1. Create a Microsoft Entra application/service principal in the correct tenant, or explicitly select the API host's managed/workload identity.
2. Assign **Reader** at each selected subscription or resource-group scope. Equivalent custom roles must cover VM, Arc machine, NIC reads and the scope permissions endpoint. Referenced NICs in other groups need Reader there too.
3. Record tenant and client IDs. In **Administration → Credentials**, add a vault entry with type **Azure / Arc**. Select that existing vault entry in the Discovery connection. Credentials are encrypted in the existing vault. Rotation uses the same form; enter the replacement secret or RSA certificate/private key pair. Tokens, private keys and secrets are omitted from API responses, run snapshots and audits.
4. Add owned CIDRs to a named inventory scope. A scope with no CIDRs imports no cloud assets. Default local CIDRs remain in Server config. VNets with overlapping addresses must use distinct scopes; never map them both to the default scope.
5. Configure selected subscription IDs, optional resource groups and exact tag filters. Test access, preview candidates, then sync. Test/preview queue asynchronous read-only runs without inventory changes.

Scopes default to **inventory only**. Enable direct management only after independently verifying that the API server routes to that scope unambiguously. Cloud discovery does not supply SSH/WinRM credentials or a remote collector. Import does not change the configured local LAN CIDRs.

The initial connector pins Azure Public Cloud endpoints: `login.microsoftonline.com` for OAuth and `management.azure.com` for ARM. Sovereign/private cloud authorities are not selectable yet. TLS verification is mandatory; redirects to alternative endpoints are rejected.

## Native/systemd, Docker and hosted identities

The normal Node API process runs the durable discovery worker every five seconds. No additional receiver port is needed. Dependencies are installed by the normal `npm ci` deployment. Back up before first startup because database migration 106 runs automatically.

For a service principal, no extra process environment is needed: save the credential in the vault and permit outbound HTTPS to the two endpoints above.

For managed identity, run WinFire on a host where the selected Azure identity is available and set `AZURE_DISCOVERY_MANAGED_IDENTITY=true` in the systemd EnvironmentFile or Docker environment. A client ID chooses a user-assigned identity; blank selects system-assigned. There is no fallback to a developer's Azure CLI login. Arc managed identity additionally requires the service account to have the documented local identity access permissions.

For workload identity, mount the platform-provided federated token file read-only and set `AZURE_FEDERATED_TOKEN_FILE` to its API-container/service path. Configure the corresponding tenant/client/federated identity in Entra. The UI cannot select arbitrary local files.

Configure trusted private CAs through Node's `NODE_EXTRA_CA_CERTS` before process startup. On a Node release supporting environment proxy handling, use its documented proxy configuration; otherwise provide a permitted direct egress path. Proxy behavior must be validated in the deployment environment. Do not disable TLS validation.

Schedules run every 5–10,080 minutes. One connection has at most one active run, and one worker executes a run at a time. Runs have 30-second HTTP timeouts, 5 attempts for throttling/service-unavailable responses, bounded Retry-After waits, 5,000 ARM requests, 100,000 resources per collection and a 15-minute deadline. Cancel through the run dialog/API. Restart recovery requeues expired two-minute leases; reconciliation is idempotent. Changing configuration or rotating a credential invalidates an older run before it writes inventory.

## API usage

All routes use `/api/v1` and the normal operator Bearer token. Readers can inspect observations/runs; administrators manage scopes, credentials, connections and resolutions. Defaults: 25 rows per page. Keep real secret values in a private payload file with mode 0600 and remove it after use.

```bash
# Create an inventory-only scope. Substitute your actual owned CIDRs.
curl -sS "$WINFIRE_URL/api/v1/inventory/scopes" \
  -H "Authorization: Bearer $WINFIRE_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Azure production VNet","kind":"azure-vnet","cidrs":["10.40.0.0/16"],"directManagement":false}'

# Payload contains type="azure", name, tenantId, clientId, authMethod and clientSecret,
# or clientCertificatePem + clientPrivateKeyPem for certificate authentication.
curl -sS "$WINFIRE_URL/api/v1/credentials" \
  -H "Authorization: Bearer $WINFIRE_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @azure-credential.json

# Create a connection with explicit subscription and scope IDs.
curl -sS "$WINFIRE_URL/api/v1/discovery/azure/connections" \
  -H "Authorization: Bearer $WINFIRE_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @azure-connection.json

# Each action returns 202 and a run ID: test, preview or sync.
curl -sS -X POST "$WINFIRE_URL/api/v1/discovery/azure/connections/$CONNECTION_ID/test" \
  -H "Authorization: Bearer $WINFIRE_TOKEN" -H 'Content-Type: application/json' -d '{}'
curl -sS "$WINFIRE_URL/api/v1/discovery/azure/runs/$RUN_ID" -H "Authorization: Bearer $WINFIRE_TOKEN"
curl -sS -X POST "$WINFIRE_URL/api/v1/discovery/azure/runs/$RUN_ID/cancel" -H "Authorization: Bearer $WINFIRE_TOKEN"
curl -sS "$WINFIRE_URL/api/v1/discovery/azure/resources?state=linked&page=1&pageSize=25&sort=name&direction=asc" -H "Authorization: Bearer $WINFIRE_TOKEN"
curl -sS "$WINFIRE_URL/api/v1/discovery/azure/resources/export?scopeId=$SCOPE_ID" -H "Authorization: Bearer $WINFIRE_TOKEN" -o azure-resources.json
curl -sS "$WINFIRE_URL/api/v1/nodes/$NODE_ID/sources" -H "Authorization: Bearer $WINFIRE_TOKEN"
curl -sS "$WINFIRE_URL/api/v1/inventory/conflicts?conflictState=all" -H "Authorization: Bearer $WINFIRE_TOKEN"
```

Example connection payload (replace placeholder IDs):

```json
{
  "name": "Azure production",
  "credentialId": "<vault-credential-uuid>",
  "subscriptions": ["<subscription-uuid>"],
  "resourceGroups": ["production"],
  "scopeId": "<inventory-scope-id>",
  "networkScopes": [],
  "tags": {"environment": "production"},
  "enabled": false,
  "intervalMinutes": 60
}
```

`networkScopes` optionally maps full VNet resource IDs to existing inventory scope IDs. A machine mapped to multiple distinct scopes is held for review. `PUT /discovery/azure/connections/:id` replaces the configuration. `PATCH /credentials/:id` edits or rotates the Azure vault entry. Omitted secret fields keep their current value; use Azure field names rather than the host-password field. Discovery has no separate credential store. `DELETE /discovery/azure/connections/:id` retains observations and requires active runs to be cancelled first.

`POST /inventory/conflicts/:id/resolve` takes `action` (`link`, `unlink`, `ignore`, `reopen`), a required `reason`, and `nodeId` for a link. Linking requires an eligible node in the same scope. Resolution changes the source binding, not node IDs or policy ownership. Full request schemas are in `/api/v1/openapi.json`.

## Troubleshooting and rollout gate

- Authentication failure: check tenant/client ID, credential expiry and certificate/key match. Rotation requires a new run.
- Identity unavailable: verify the explicit host environment, local permissions or federated token mount.
- Partial scope: inspect run errors for missing whole-scope Reader or referenced NIC access. An empty result is not assumed complete when permissions cannot be checked.
- No inventory assets: inspect Resources for out-of-scope records, missing addresses and identity conflicts. Do not broaden CIDRs simply to clear the queue.
- Unknown version: Azure VM configuration usually reports an OS family, not the installed guest build. Use Arc or authenticated host facts for version information.

Before deployment, back up the SQLite database using its online backup mechanism, the vault master key/secrets, PKI and the existing data directory. Stop the API for a file-level copy; copying an active WAL database alone is insufficient. To roll back, stop the new API and restore the pre-upgrade application and matching database/key backup together. Do not roll back just the schema over newly imported records.

Local fixture validation is separate from live approval. Keep PLAN 28-06 open until an authorized tenant pilot verifies Windows/Linux VMs, already-onboarded Arc, exact selected-scope counts, one existing-node match, public-peer exclusion, unchanged management state and a scheduled run after restart. The remaining policy, telemetry and collector tasks in §28.4 are separate rollout gates.

## Primary references

- [Azure Identity for JavaScript](https://github.com/Azure/azure-sdk-for-js/blob/main/sdk/identity/identity/README.md)
- [Azure Arc machine list and fields](https://learn.microsoft.com/en-us/rest/api/hybridcompute/machines/list-by-resource-group?view=rest-hybridcompute-2025-01-13)
- [Azure network interface inventory](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-interfaces/list-all)
- [Azure Arc identity authorization](https://learn.microsoft.com/en-us/azure/azure-arc/servers/security-identity-authorization)

## Capability coverage and learning readiness

Reports → **Capabilities** shows separate freshness for discovery, authentication, facts,
firewall reads, firewall writes, policy readback, events and verification. Each capability has
its own supported denominator; SNMP and Arc observations never imply firewall-write capability.
The report uses server-side search/filter/pagination (25 rows). Read it through
`GET /api/v1/reports/capabilities` or `GET /api/v1/nodes/:id/capabilities`.
Administrators can read/update freshness thresholds in hours using
`GET /api/v1/settings/coverage` and `PUT /api/v1/settings/coverage`.

Automatic learning requires successful, current event collection. The Windows agent now sends
`POST /api/v1/agents/:id/telemetry-health` over its existing mutually authenticated channel after
collection, including empty reads, backlog status and actual Filtering Platform Connection success
auditing state. Older agents can continue shipping events, but must be upgraded before automatic
learning can finish using the new collection-health gate. A heartbeat alone is insufficient.
Failed or stale collection leaves learning pending with an actionable error. Quiet healthy hosts
can still finish learning once the agent confirms empty successful reads with auditing enabled.
