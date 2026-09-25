# Policy safety and traffic context

## Delivery status

P1 is **in progress**, not production-complete. Available now: capability evidence,
pinned historical replay and observe-only jobs, enrolled flow/syslog imports, selected
Azure VNet blob reads, read-only cloud network context, application metadata review,
scoped Windows templates and exception review records.

Staged Windows rollout and Windows/Linux incident containment are implemented as
controlled pilots, with native recovery, per-node outcomes and explicit restore.
Effective Windows policy reads support counterfactual replay. Application sources
produce reviewed proposals, dependency notifications and staged exception withdrawal.

P1 remains open for real exporter captures, actual Azure samples/correlation, and
controlled Windows/Linux management-path recovery acceptance. The user has not yet
provided an Azure pilot tenant or disposable fleet hosts. Production enforcement is
not enabled by these additions; a review records a decision, not proof of safety.

## Capability coverage

Open **Reports → capabilities**. Evidence covers discovery, authentication, facts,
firewall read/write, policy readback, events, flows and verification. Each operation
is fresh, stale, missing, failed or unsupported. Unsupported operations do not enter
that capability's denominator. Scope, source and transport selectors show eligible
and excluded counts. Freshness thresholds are stored server-side and editable by
administrators. Existing authentication health and notification records are reused.

SNMP polls establish SNMP identity/facts/verification, not endpoint enforcement.
Cloud resource observations do not establish guest authentication. Offline agents
cannot qualify for automatic learning promotion. Training additionally checks agent
collector health or Windows auditing and drains its event backlog before promotion.

## Policy impact

Open a policy in **Policy Studio → Policy impact**. Choose explicit targets and a
historical window (maximum 30 days) or an observe window (maximum 24 hours). Historical
input is copied before evaluation; log compaction or deletion cannot change a queued
replay. Maximum 100 targets and 100,000 observations per run. Evaluation batches are
bounded and scheduled fairly. Cancellation and progress survive process restarts.

The draft, baseline, target memberships, policy assignments and input evidence are
pinned. A policy version or target/group change invalidates review approval. Results
include matching rule IDs, missing inputs, flow identity and applications when the
original event captured them. Profiles, program paths, local account qualifiers and
schedule windows are evaluated only when evidence supports them. Unsupported
platforms and missing telemetry remain indeterminate. Full host defaults, foreign
rules and authenticated bypass context are not currently captured, so permissive
changes cannot be certified as newly allowed. An empty replay is not a safety pass.

```bash
curl -H "Authorization: Bearer $WINFIRE_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"baseVersionId":"VERSION_ID","nodeIds":["NODE_ID"],"kind":"historical","from":"2026-09-24T00:00:00Z","to":"2026-09-25T00:00:00Z"}' \
  "$WINFIRE_URL/api/v1/policies/POLICY_ID/simulations"
curl -H "Authorization: Bearer $WINFIRE_TOKEN" \
  "$WINFIRE_URL/api/v1/policy-simulations/RUN_ID/results?outcome=indeterminate&page=1&pageSize=25"
```

## Network-device telemetry

Open **Activities → Traffic sources**. Enroll an existing local collector asset,
choose its exact format and enable it. No receiver port opens by default. API uploads
require administrator privileges. Public endpoints remain traffic peers and are never
created as inventory assets by this importer.

Supported decoder contracts:

| Format | Current support | Limitations |
| --- | --- | --- |
| NetFlow v9 | Cisco/RouterOS standard data templates; exporter/domain-separated cache | Standard sampling options are decoded for recognized system/domain/interface/template scopes; ambiguous or unsupported scopes remain unknown. |
| IPFIX v10 | Standard information elements, enterprise-field skipping, variable lengths, IPv4/IPv6, interface, NAT, counters and inline sampling | Enterprise-specific semantics are not inferred. |
| PF filterlog | pfSense/OPNsense CSV payload, IPv4/IPv6, explicit pass/block, interface and tracker | Other vendor messages are rejected; forwarding direction is retained as source evidence, not treated as endpoint direction. |
| RouterOS firewall | Connection log with `proto … source:port->destination:port` | A log prefix does not prove allow/drop; verdict stays unknown. |
| SonicWall key/value | `src`, `dst`, protocol, ports, interfaces and explicit `fw_action` | Numeric message IDs alone do not prove a verdict. CEF is not this decoder. |

Templates expire after 30 minutes. The cache is bounded to 4,096 templates and 1,024
exporter/domain sessions. Missing templates, malformed packets and exporter resets
are visible. Identical datagrams are suppressed within the bounded retransmission
window. Late datagrams older than the current export timestamp are dropped rather
than decoded with potentially incompatible templates. No process/account is invented.

```bash
curl -H "Authorization: Bearer $WINFIRE_TOKEN" -H 'Content-Type: application/json' \
  --data '{"name":"Core exporter","nodeId":"NODE_ID","format":"ipfix-v10","sourceIp":"192.168.88.4","enabled":true}' \
  "$WINFIRE_URL/api/v1/telemetry/exporters"
curl -H "Authorization: Bearer $WINFIRE_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @syslog-capture.json \
  "$WINFIRE_URL/api/v1/telemetry/exporters/EXPORTER_ID/syslog"
```

`syslog-capture.json` contains `captureKey` and a `lines` array. Replaying the same key
and content is idempotent; changing content under an existing key returns 409.
Binary uploads use `/datagram` with a `base64` property. Metadata includes original
direction/time, NAT and sampling where supplied. Traffic remains visible in Activities,
Mapping and Internet. Counts are **observations**, not distinct end-to-end connections;
endpoint and cloud/device samples must not be added as if they were unique sessions.

### Live receiver configuration

- `TELEMETRY_UDP_PORT`: opt-in NetFlow/IPFIX UDP port, 1024–65535.
- `TELEMETRY_SYSLOG_TLS_PORT`: opt-in TLS syslog port, 1024–65535.
- `TELEMETRY_BIND`: defaults to `127.0.0.1`; choose an explicit collector interface.
- `TELEMETRY_UDP_IPV6=true`: use an IPv6 UDP socket.
- `TELEMETRY_TLS_CERT`, `TELEMETRY_TLS_KEY`, `TELEMETRY_TLS_CA`: PEM files for TLS
  syslog; clients must present certificates issued by the configured CA.

For TLS enroll the client's SHA-256 certificate fingerprint (64 hex characters) and
source IP. Exactly one enabled format must match the authenticated sender. Supports
newline and RFC 6587 octet-counted frames. Devices without compatible TLS export can
send through a trusted TLS relay; enroll the relay identity and source address.
Do not expose plaintext UDP publicly. Restrict OS/network ACLs to enrolled exporters;
UDP source matching is not cryptographic authentication. Enforce those ACLs before
binding a receiver beyond loopback.

The receiver queue is 256 messages, with at most 64 TLS connections and 16 KiB syslog
records. Overflow drops are visible at `/telemetry/receiver-status`. Per-exporter
accepted/rejected/duplicate/missing-template totals are visible in the UI and API.
Metadata and capture checkpoints follow `log_retention_days` (default 90), pruned in
bounded batches. Replays after retention can create new observations; deduplication
is not an unlimited archival guarantee. Receivers require a server restart after
environment changes.

## Azure VNet logs and network configuration

Choose an `azure-vnet` traffic source, then **Import capture**. Select a vault Azure
credential, storage account, container and an existing blob path. The credential
needs **Storage Blob Data Reader** for that container, separately from ARM Reader.
Tokens use the Storage audience. Only HTTPS public-Azure blob endpoints are accepted;
redirects are rejected. No logging resources, diagnostics settings or paid services
are enabled. Reads still incur the storage account's normal transaction charges.

Version 4 VNet tuples retain capture GUID, target resource, ACL/rule, MAC, direction,
flow state, encryption and counters. Both second and millisecond epoch forms are
accepted. Legacy NSG schema is rejected explicitly. Maximum 16 MiB / 10,000 tuples
per import. Conditional GET uses ETags; stable tuple keys handle appended, rotated
or late captures without reinserting existing tuples. State B/C/E is not fabricated
as an endpoint firewall allow verdict. Actual tenant sample validation remains open.

```bash
curl -H "Authorization: Bearer $WINFIRE_TOKEN" -H 'Content-Type: application/json' \
  --data '{"credentialId":"AZURE_VAULT_ID","account":"storageaccount","container":"insights-logs-flowlogflowevent","blob":"SELECTED/PATH/PT1H.json"}' \
  "$WINFIRE_URL/api/v1/telemetry/exporters/EXPORTER_ID/vnet-blob"
curl -X POST -H "Authorization: Bearer $WINFIRE_TOKEN" \
  "$WINFIRE_URL/api/v1/discovery/azure/connections/CONNECTION_ID/network-context"
```

**Mapping → Cloud context** reads VNets (including embedded subnets/peerings), NICs,
NSGs and route tables inside the configured connection scope. Records are labeled
configured, not observed or actively verified. Absence on a later read does not erase
previous evidence. Service tags, NAT, effective routes and end-to-end reachability
are not inferred. Query `/mapping/cloud-context` for pagination.

## Application ownership and templates

Node details contain **Application ownership**. Submit a proposal, inspect effective
values and dynamic-group/policy impact, then approve with a reason. Precedence:
manual > approved Azure tag > AD OU > group. Each source retains its reference.
Source imports currently require an explicit proposal; automatic refresh/alerts are
still pending. Stale proposals require a fresh preview. Fields: application,
environment, workload role, business owner and criticality. Dynamic group conditions
can use these fields through the existing API. **Mapping → Applications** links
observed dependencies to filtered firewall events.

**Policy Studio → Rule lifecycle and templates** provides version 1 Windows templates
for directory services, DNS, Kerberos, SMB files, backup and management. Destination
assets must have the required reviewed endpoint role. Templates use their explicit
local addresses. Backup/management require explicit ports; directory templates omit
broad RPC ranges and SMB. Templates replace a draft after confirmation and never apply
rules. Save and evaluate through the existing Policy Studio workflow.

## Exception review

Attach owner, justification, request reference, review date and optional expiry to a
saved, app-owned rule. Review queues support due/expired filters and pagination.
Notifications reuse Security policy destinations. Recertification and retirement
requests require reasons and produce audit records. JIT/local-identity rules are
excluded from ordinary exception retirement. Foreign rules cannot be selected.

A retirement request produces a withdrawal draft; it does not remove host rules.
A reviewed staged draft that removes a requested or expired exception links the exception to the deployment. It becomes retired only after every target confirms the withdrawal; partial/offline outcomes remain pending, and restoring the deployment reopens retirement. Expiry sends review notifications rather than silently bypassing deployment review. Hygiene
flags exact equivalent matches, contained matches, ordinary Windows block/allow overlaps and broad allows. It does not claim
that an unobserved rule is unused. Full overlap analysis requires additional platform
semantics and sufficient observation coverage.

## References and verification

- [Windows firewall precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)
- [Cisco NetFlow export formats](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/5-0-3/user/guide/format.html)
- [IPFIX information elements](https://www.iana.org/assignments/ipfix/ipfix.xhtml)
- [pfSense raw filter format](https://docs.netgate.com/pfsense/en/latest/monitoring/logs/raw-filter-format.html)
- [RouterOS Traffic Flow](https://help.mikrotik.com/docs/spaces/ROS/pages/21102653/Traffic+Flow)
- [SonicOS log reference](https://www.sonicwall.com/techdocs/pdf/sonicos-6-5-1-log-events-reference-guide.pdf)
- [Azure VNet flow-log schema](https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview)

Run `npm test`, `npm run build` and `npm run docs:api`. Controlled fixtures do not
replace live exporter, tenant, host recovery or containment/restore acceptance gates.

## Staged rollout and recovery

In Policy Studio, select target assets under **Policy impact**, optionally **Read
effective host policy**, then start and review a completed evaluation. Effective
context is cached for five minutes and pinned into the evaluation; a later context
capture invalidates old approval. Unsupported platforms/qualifiers stay indeterminate.
Replay compares the candidate against the saved policy plus captured foreign rules
and defaults. Historical traffic does not establish historical firewall configuration.

Under **Staged deployment**, select that evaluation, canaries, application TCP ports,
batch size, recovery duration, start/end window and reason. Preview covers the full
assigned target set. The default pause threshold is zero failures. A configured later-batch failure budget can continue after confirmed restoration; canary failures and unconfirmed restores always pause. A partial rollout never publishes the candidate version. The API pins a
candidate version without publishing it; canary health must pass before later batches.
Every Windows target gets a SYSTEM scheduled recovery task before mutation. Recovery
uses the exact owned group snapshot; foreign groups and concurrently changed rules
are not overwritten. After successful application and health readback, the host
transaction commits; only after all targets commit is the candidate published.
Cancel/restore reports each target and retries unresolved restoration explicitly.

Current staged recovery support is modern Windows over WinRM/WinRMS. Agent, legacy
Windows and Linux staged-policy writes are excluded. Linux containment below has its
own kernel expiry adapter. To conduct an authorized disposable-host pilot, set
`WINFIRE_POLICY_SAFETY_PILOT_NODES` to explicit inventory node IDs. It defaults empty.
This is not a production-readiness override. Do not select ordinary production hosts
before the live recovery acceptance recorded in PLAN has passed.

```bash
curl -H "Authorization: Bearer $TOKEN" -X POST \
  "$BASE/api/v1/nodes/$NODE_ID/policy-context"

curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d @reviewed-rollout.json "$BASE/api/v1/policy-deployments/preview"
# The same reviewed payload starts an authorized pilot:
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d @reviewed-rollout.json "$BASE/api/v1/policy-deployments"
curl -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/policy-deployments/$DEPLOYMENT_ID"
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason":"Restore the pilot baseline"}' \
  "$BASE/api/v1/policy-deployments/$DEPLOYMENT_ID/restore"
```

`reviewed-rollout.json` requires `simulationId`, `canaryNodeIds`, `healthPorts`,
`windowStart`, `windowEnd` and `reason`; optional `batchSize`, `recoverySeconds` and
`maxFailures` have documented OpenAPI limits. Health probes originate at the API
server and test authentication plus TCP availability, not a full application transaction.

## Incident containment

Open **Activities → Incident containment**. Select assets and/or a node group,
180–3600-second duration, reason, optional incident ID and protected CIDRs. Preview
shows included hosts, exclusions and restoration scope. The server also protects
reviewed DNS/domain-controller/management roles, loopback and link-local dependencies.
Set `WINFIRE_CONTAINMENT_CONTROL_CIDRS` to verified controller/NAT management CIDRs;
without these and explicit pilot node IDs, starting containment is rejected.

Windows uses explicit block ranges excluding protected peers because ordinary allow
rules do not override a matching Windows block. All profiles must be enabled and
IPsec/authenticated bypass must be absent. Effective rule readback and independent
management health are required. Linux requires SSH, Python 3, nftables and passwordless
sudo. It installs a unique incident table with protected-peer returns and a kernel
protocol-set lease; lease expiry stops matching the drop rules even if the API or SSH
connection disappears. Flow-offload configurations are rejected. Forwarded/container
namespaces are outside this host INPUT/OUTPUT containment scope.

Restore removes only the incident-owned table/group and confirms readback. Concurrent
changes are surfaced instead of overwritten. Failed/offline outcomes remain visible.
No arbitrary script can be supplied in a containment request. Production acceptance
still requires controlled SSH/WinRM isolation and reconnect/restore on disposable hosts.

```bash
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"nodeIds":["NODE_ID"],"seconds":600,"reason":"Incident investigation","incidentId":"INC123","protectedCidrs":["192.168.1.10/32"]}' \
  "$BASE/api/v1/containments/preview"
# POST the reviewed payload to /containments to start an authorized pilot.
curl -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/containments?page=1&pageSize=25"
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"reason":"Investigation finished"}' "$BASE/api/v1/containments/$INCIDENT_ID/restore"
```

## Automatic application metadata proposals

**Mapping → Applications → Application metadata sources** configures approved Azure
tag-to-field mappings, AD OU mappings and node-group mappings. Switches enable proposal
refresh and notifications for newly observed dependency pairs. The worker processes
bounded batches of 200 nodes; `POST /application-proposals/refresh` runs another batch.
Review proposals under each asset’s **Application ownership** details. Tag changes and
removals, OU moves and removed mappings require review; removing a higher-priority
source falls back to other approved sources. Manual values retain highest precedence.
Dynamic node-group forms include all five application metadata fields.

```bash
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -X PUT \
  -d '{"enabled":true,"dependencyAlerts":true,"rules":[{"id":"app-tag","source":"azure-tag","tag":"application","field":"application"}]}' \
  "$BASE/api/v1/settings/application-metadata"
```

## Native Linux verification

The suite exercises kernel timeouts, repeat restores, foreign-rule preservation and
concurrent-change rejection in a new user/network namespace where supported:

```bash
unshare --user --map-root-user --net python3 api/tests/linux_containment_native.py
```

This does not modify the host firewall and does not replace a live SSH/control-path
pilot. PowerShell syntax is checked locally; Windows native recovery still needs its
controlled host acceptance run. Additional protocol references:
[NetFlow v9 options](https://www.rfc-editor.org/rfc/rfc3954.html),
[IPFIX options](https://www.rfc-editor.org/rfc/rfc7011.html), and
[nftables timeout sets](https://wiki.nftables.org/wiki-nftables/index.php/Sets).
