# API usage and curl examples

The API is the control surface used by the Vue interface. Base URL: `https://winfire.example.com/api/v1`. Use `/api/v1/openapi.json` for the live machine-readable contract and [API_ROUTES.md](API_ROUTES.md) for every registered method/path, authentication scheme, explicit permission gate, handler link and published schema. Run `npm run docs:api` after adding routes.

Examples use Bash, curl and jq. Replace example addresses/IDs with your environment. Mutating examples change state or contact the named host; run them on a test target first. JSON files containing credentials should have restrictive permissions and be removed after use. Do not use `curl -k` for a production control-plane session.

## Authentication

```bash
BASE='https://winfire.example.com/api/v1'

curl --fail-with-body "$BASE/health"
curl --fail-with-body "$BASE/openapi.json" -o openapi.json

# Create login.json privately with your email/password and optional current totp:
# {"email":"owner@example.com","password":"your-password","totp":"123456"}
chmod 600 login.json
LOGIN=$(curl --fail-with-body "$BASE/auth/login" \
  -H 'Content-Type: application/json' --data-binary @login.json)
TOKEN=$(printf '%s' "$LOGIN" | jq -er '.accessToken')
REFRESH=$(printf '%s' "$LOGIN" | jq -er '.refreshToken')
curl --fail-with-body "$BASE/auth/me" -H "Authorization: Bearer $TOKEN"
```

Access tokens last 15 minutes. Refresh tokens last up to 30 days and rotate on use. Store **both** replacement tokens after refresh; do not repeatedly reuse the old refresh token. Account suspension/session revocation invalidates access even before token expiry.

```bash
LOGIN=$(printf '%s' "$REFRESH" | jq -Rs '{refreshToken:.}' | \
  curl --fail-with-body "$BASE/auth/refresh" -H 'Content-Type: application/json' --data-binary @-)
TOKEN=$(printf '%s' "$LOGIN" | jq -er '.accessToken')
REFRESH=$(printf '%s' "$LOGIN" | jq -er '.refreshToken')

# Log out this refresh session when finished:
printf '%s' "$REFRESH" | jq -Rs '{refreshToken:.}' | \
  curl --fail-with-body "$BASE/auth/logout" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' --data-binary @-
```

AD login uses `/auth/ad/login` with email/password and optional TOTP and requires HTTPS/configured directory authentication. The public authenticator enrollment endpoints have separate rate limits and HTTPS requirements. Enrolled agents use client certificates instead of operator bearer tokens; Internet extension devices use their own issued bearer tokens; WEF uses node-scoped HMAC tokens.

Permission gates map `auditor → portal.read`, `editor → portal.edit`, `admin → portal.admin`, and `owner → portal.owner`. Actual authorization reads role permissions, so custom roles can differ. Resource visibility, credential ownership and grants are additional checks. A 403 is not solved merely by knowing an object ID.

## Conventions and errors

- JSON requests use `Content-Type: application/json`; the general body limit is 2 MB. WEF is a SOAP/XML exception.
- IDs are returned by create/list calls; do not assume hostname equals node ID.
- Times are ISO 8601 with UTC or a timezone offset. Use `--get --data-urlencode` for filters containing CIDRs, dates, names or spaces.
- Pagination response shapes differ by route: inventory/logs/import history use `items`; mapping uses `rows`. Use the endpoint's `total`, page and page size rather than counting only displayed rows.
- GET is read-only unless the route's documented behavior explicitly says otherwise. POST actions may contact managed devices, queue jobs or change firewall policy.
- 400: invalid input; 401: missing/expired identity; 403: insufficient permission; 404: absent/inaccessible object; 409: conflict or unmet prerequisite; 413: request too large; 429: rate limit; 501: unsupported feature in this build; 503: required service/configuration missing.
- Errors generally include `error`; onboarding calls can include `onboardingError` with code/title/summary/remediation. Credential tests can return HTTP 200 with `success:false`; check the JSON body.
- Some legacy OpenAPI operations have generic request/response schemas. The generated reference links directly to each handler's full validation. Do not treat a generic schema as permission to send arbitrary fields.

## Server configuration and local scope

```bash
curl --fail-with-body "$BASE/settings/server" -H "Authorization: Bearer $TOKEN"
curl --fail-with-body -X PATCH "$BASE/settings/server" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"fqdn":"winfire.example.com","publicBaseUrl":"https://winfire.example.com","localCidrs":["192.168.50.0/24","10.20.0.0/16"]}'
```

Use your effective environment-owned URL/FQDN when present; conflicting values return 409. This endpoint accepts a complete `localCidrs` array; omitting it defaults to an empty scope. Read the current configuration first and preserve all intended CIDRs.

## Inventory: search, filter, sort, details

```bash
curl --fail-with-body --get "$BASE/nodes" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'page=1' --data-urlencode 'pageSize=25' \
  --data-urlencode 'search=linux' --data-urlencode 'filter=managed' \
  --data-urlencode 'sort=hostname' --data-urlencode 'direction=asc'
curl --fail-with-body "$BASE/nodes/$NODE_ID" -H "Authorization: Bearer $TOKEN"
```

`filter`: `all`, `managed`, `unmanaged`, `reachable`, `unreachable`. Default sort is `priority` (managed/learning first); other supported keys include `hostname`, `address`, `status`, `mode`, with `asc`/`desc` direction. Page size defaults to 25, maximum 500. **Unparameterized `GET /nodes` returns a legacy array**; pass page parameters for the paginated contract. Node details include normalized OS fields, management verification, classification evidence, VM information, facts and optional `dhcpLease` evidence.

Create a manual node and later select management type/credentials:

```bash
curl --fail-with-body "$BASE/nodes" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"hostname":"server-01","fqdn":"server-01.example.com","ip":"192.168.50.10","connectionMode":"agentless","credentialIds":[]}'

# credentials.json contains IDs, not secrets; this replaces direct node bindings.
# {"deviceType":"esxi","managementType":"api","credentialIds":["ESXI_CREDENTIAL_ID"]}
curl --fail-with-body -X PATCH "$BASE/nodes/$NODE_ID" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data-binary @credentials.json

curl --fail-with-body -X POST "$BASE/nodes/$NODE_ID/probe" -H "Authorization: Bearer $TOKEN"
curl --fail-with-body -X POST "$BASE/nodes/$NODE_ID/facts/refresh" -H "Authorization: Bearer $TOKEN"
```

Manual node creation starts the normal training/onboarding workflow. Use DHCP import for passive enrichment without that active creation workflow. `deviceType` supports `auto`, `linux`, `switch`, `firewall`, `router`, `printer`, `hypervisor`, `esxi`, `other`; `managementType` supports `auto`, `ssh`, `snmp`, `agentless`, `agent`, `api`, `manual` (device-specific checks still apply).

## Vault and preflight

Create `credential.json` privately, for example:

```json
{"name":"Linux discovery","type":"ssh","username":"winfire","password":"replace-with-secret","visibility":"private","priority":100}
```

Credential types: `local`, `domain`, `esxi`, `ssh`, `snmp-v2c`, `snmp-v3`. SSH can use `privateKey`, `passphrase`, `hostKeyFingerprint`, `port`; SNMP v2c uses `community`; v3 uses `username`, `securityLevel`, `authProtocol`, `authKey`, `privProtocol`, `privKey` according to the selected security level. Returned records omit secrets.

```bash
curl --fail-with-body "$BASE/credentials" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @credential.json
curl --fail-with-body "$BASE/credentials/$CREDENTIAL_ID/preflight" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"host":"192.168.50.10"}'
curl --fail-with-body "$BASE/credentials/health" -H "Authorization: Bearer $TOKEN"
```

Preflight supports Windows local/domain and SSH credentials, without creating an asset. `POST /credentials/{id}/test` accepts `{"nodeId":"..."}` and requires an existing assignment. Rotate a stored secret with `PATCH /credentials/{id}` using the changed write-only secret fields; test before fleet use. Use successful SNMP polling or ESXi facts collection to verify those credential types.

## Discovery scans and recurring schedules

```bash
curl --fail-with-body "$BASE/discovery/scans" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data '{"cidrs":["192.168.50.0/24"]}'
curl --fail-with-body "$BASE/discovery/scans/$SCAN_ID" -H "Authorization: Bearer $TOKEN"

curl --fail-with-body "$BASE/discovery/schedules" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"name":"Office LAN","cidrs":["192.168.50.0/24"],"intervalMinutes":60,"enabled":true}'
curl --fail-with-body -X POST "$BASE/discovery/schedules/$SCHEDULE_ID/run-now" -H "Authorization: Bearer $TOKEN"
curl --fail-with-body -X PATCH "$BASE/discovery/schedules/$SCHEDULE_ID" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data '{"enabled":false}'
```

Scans return queued identifiers; poll the scan resource for completion/results. Recurring intervals are 5–10,080 minutes; overlapping runs are blocked. Completed scheduled scans include new/dark/changed diffs. A paused schedule must be enabled before run-now. Deleting a schedule retains scan history.

SNMP uses `/discovery/snmp-targets` CRUD and `POST /discovery/snmp-targets/{id}/poll`; assigned SNMP credentials on nodes also support polling. Linux defaults use `/settings/discovery-linux`. ARP candidate review/processing uses `/discovery/passive-candidates` and `/discovery/passive-candidates/process`.

## DHCP import

See [DHCP import](DHCP_IMPORT.md) for export instructions, full payload and matching rules.

```bash
curl --fail-with-body "$BASE/discovery/dhcp/preview" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @winfire-dhcp-001.json
curl --fail-with-body "$BASE/discovery/dhcp/import" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @winfire-dhcp-001.json
curl --fail-with-body "$BASE/discovery/dhcp/imports?page=1&pageSize=25" -H "Authorization: Bearer $TOKEN"
```

## Node groups and bulk triage

```bash
# Static group:
curl --fail-with-body "$BASE/node-groups" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data '{"name":"Pilot hosts"}'
# Dynamic group:
curl --fail-with-body "$BASE/node-groups" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"name":"Office subnet","dynamic":{"enabled":true,"match":"all","rules":[{"field":"ip","operator":"cidr","value":"192.168.50.0/24"}]}}'
curl --fail-with-body -X POST "$BASE/node-groups/$GROUP_ID/refresh" -H "Authorization: Bearer $TOKEN"

# triage.json: {"nodeIds":["NODE_ID_1","NODE_ID_2"],"action":"flagged","note":"Review ownership"}
curl --fail-with-body "$BASE/nodes/triage/bulk" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @triage.json
```

Bulk actions: `assign_and_retry` (with `credentialId`), `flagged`, `excluded`, `none` (restore). Maximum 200 IDs; inspect each result rather than treating the batch as uniformly successful. Dynamic groups evaluate server-side and reject direct manual member mutation while enabled.

## Events and mapping

```bash
curl --fail-with-body --get "$BASE/logs/search" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'eventType=firewall' --data-urlencode 'action=block' \
  --data-urlencode 'page=1' --data-urlencode 'pageSize=100' \
  --data-urlencode 'sortBy=time' --data-urlencode 'sortDir=desc'

# Accounts tab equivalent: Windows successful logons
curl --fail-with-body --get "$BASE/logs/search" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'eventType=logon' --data-urlencode 'eventId=4624' --data-urlencode 'action=logon'

curl --fail-with-body "$BASE/mapping/filter-options" -H "Authorization: Bearer $TOKEN"
curl --fail-with-body --get "$BASE/mapping" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'subnet=192.168.50.0/24' --data-urlencode 'external=1' \
  --data-urlencode 'page=1' --data-urlencode 'pageSize=100'
curl --fail-with-body --get "$BASE/mapping/topology" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "switchId=$SWITCH_ID" --data-urlencode 'subnet=192.168.50.0/24'
curl --fail-with-body --get "$BASE/mapping/arp" -H "Authorization: Bearer $TOKEN" \
  --data-urlencode "switchId=$SWITCH_ID" --data-urlencode 'limit=500'
```

Logs also accept `nodeId`, `direction`, `program`, `challengeId`, `protocol`, `srcIp`, `dstIp`, `port`, `account`, `from`, `to`, `hideLoopback`. `eventType` is `firewall`, `logon`, or `all`; log page size maximum 500. Sort keys include time, node, eventId, action, direction, srcIp, dstIp, port, program, account.

Mapping filters are server-side and intersect before totals/paging. Subnet and switch must match the same endpoint; external peers are kept to show the traffic crossing that scope. See the generated reference for graph limits and full query descriptions.

## Directory, policy and reports

```bash
curl --fail-with-body -X POST "$BASE/directory/test" -H "Authorization: Bearer $TOKEN"
curl --fail-with-body -X POST "$BASE/directory/sync" -H "Authorization: Bearer $TOKEN"
curl --fail-with-body "$BASE/policies" -H "Authorization: Bearer $TOKEN"
curl --fail-with-body "$BASE/learning-sessions" -H "Authorization: Bearer $TOKEN"
```

Directory test/sync uses the saved `/settings/directory` configuration. Policy graphs and compiled rules have richer schemas: create/revise through `/policies` and `/policies/{id}/versions`, inspect differences and verification, then assign through `/policies/{id}/assignments`. Use the handler/schema reference for the exact graph payload and apply/sync routes. Learning sessions can own a generated policy and block manual changes until review. Report/download routes can return CSV or PDF instead of JSON; use `curl -o report.csv`/`report.pdf` with the applicable endpoint and authorization header.

## JIT MFA access

Read [JIT MFA](JIT_MFA.md) before creating a segment. Creating a segment does not make an unsafe firewall gate safe. A sample segment payload in `segment.json`:

```json
{
  "name":"Pilot RDP",
  "nodeId":"TARGET_NODE_ID",
  "port":3389,
  "mode":"agentless",
  "mfaProvider":"totp",
  "allowedUpns":["operator@example.com"],
  "sourceIp":"192.168.50.0/24",
  "ttlMinutes":10,
  "portalEnabled":true,
  "autoPromptEnabled":false,
  "failOpen":false
}
```

```bash
curl --fail-with-body "$BASE/segments" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @segment.json
curl --fail-with-body "$BASE/segments/access" -H "Authorization: Bearer $TOKEN"

# Request as the allowed user, from the actual source machine, using a fresh code:
curl --fail-with-body "$BASE/segments/$SEGMENT_ID/access" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data '{"code":"123456"}'
curl --fail-with-body "$BASE/segments/access/grants" -H "Authorization: Bearer $TOKEN"
curl --fail-with-body -X POST "$BASE/segments/access/grants/$GRANT_ID/revoke" \
  -H "Authorization: Bearer $TOKEN"
```

A group segment also needs `nodeId` in its access request. The source IP is derived from the HTTP request. Do not run the access example from the server expecting it to grant a different workstation. Entra segments use `/segments/{id}/entra/start` and the browser authorization flow, not the TOTP endpoint. Explicit revoke permits the owning user or an administrator according to the route checks.

## Agent mTLS example

After authorized enrollment (single-use token plus CSR over HTTPS), use the issued agent ID/certificate/key:

```bash
curl --fail-with-body "$BASE/agents/$AGENT_ID/heartbeat" \
  --cacert server-ca.crt --cert agent.crt --key agent.key \
  -H 'Content-Type: application/json' \
  --data '{"version":"0.1.0","mode":"pull","platform":"windows"}'
```

The TLS peer certificate must reach the API listener itself. A normal proxy header carrying a certificate string is not accepted as mTLS. Production enrollment/deployment additionally requires the configured PKI and signed package prerequisites described in [Installation](INSTALLATION.md).

## AI telemetry APIs and MCP

[AI usage API examples](AI_USAGE.md#2-rest-quick-start) cover reporter enrollment, durable bounded `POST /api/v1/ai/usage:batch` receipts, DNS answers, matching list/summary/export filters and credential lifecycle. Operator read/admin credentials are separate from node-scoped reporter credentials. `/mcp/ai-usage` uses OAuth `ai:report`; [remote and stdio setup](AI_USAGE.md#3-remote-mcp-with-a-maintained-oauth-provider) documents the supported SDK and protocol paths.
