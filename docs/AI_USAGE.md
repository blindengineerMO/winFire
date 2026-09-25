# AI usage: setup, reporting, observations and operations

WinFire records **reported operations** separately from **observed AI-service traffic**.
The feature is metadata only: no prompts, model responses, tool arguments, transcripts or
credentials belong in a report. Local models and private gateways can report without an
Internet connection. Network visibility alone cannot reveal tokens, prompts, the human user,
or whether an allowed connection completed an AI operation.

## 1. Install and enable

Use the normal [installation procedure](INSTALLATION.md): Node 20+, `npm ci`, `npm run build`,
then start the API. Migration `104_ai_usage.cjs` creates the reporting, catalog, receipt,
evidence and durable work-queue tables. Back up the SQLite database with its backup API before
upgrading. Do not copy an active database without accounting for WAL files.

The server starts a bounded AI worker every second. It processes up to 50 queued jobs,
50 retained firewall rows, 50 retained browser rows and 50 enrichment rows per tick.
It stores cursors transactionally; a restart resumes processing. Original Activities,
Mapping and Internet data remain available. Collection is enabled by default, retention
is 90 days, and both correlation and DNS evidence windows default to 120 seconds.

Open **Administration → AI usage**:

1. **Reporters:** enroll a reporter, choose its coverage and authorized node(s), and copy the
   one-time enrollment credential into its environment/credential store.
2. **Service catalog:** review built-in rules and add organization-specific gateways or private
   endpoints. Every change records a new version and triggers retained-event reclassification.
3. **Collection settings:** use the collection switch, retention, correlation, DNS and stale
   heartbeat settings; inspect backlog, drops, schema errors and last successful work.

The reporter credential authorizes only telemetry ingestion for its bindings. It cannot log
into the operator UI, read fleet data, change policies or read the credential vault.
Operator roles `auditor` and above can read AI data; `admin`/`owner` can change configuration.
Existing node-group resource permissions are checked when filtering by group.

### Coverage and identity

| Enrollment coverage | Intended producer | Meaning |
|---|---|---|
| `self-reported` | Agent explicitly calls an MCP tool or REST helper | Voluntary report; completeness unknown |
| `instrumented` | Hook, application wrapper or GenAI span adapter | Only operations captured by that integration |
| `collector` | Explicitly authorized multi-node collector | Each report must identify one of its authorized nodes, or remain unmapped |

A reporter with one binding can omit `nodeId`; the API supplies that node. A reporter with
multiple/no bindings and no `nodeId` remains unmapped. A supplied unauthorized node is rejected.
`actorId` is set by an administrator at enrollment, never trusted from an incoming report.
Unknown actors remain unknown. A shared MCP runner is not automatically the workload's host.

The suggestions endpoint accepts IP, MAC, hostname and event time. It returns only candidates
already in that reporter's authorization scope, with current inventory/agent and active DHCP
lease evidence. It never silently rebinds a reporter. NAT, VPN, reused addresses, VMs and shared
hosts still require an administrator to review the unique identity before changing bindings.

## 2. REST quick start

Use an operator token from the normal login flow. Shell examples use placeholders and keep
credentials in environment variables; avoid saving real credentials in shell scripts or logs.
`jq` is used only for selecting JSON fields.

```bash
export WINFIRE_URL=https://winfire.example.com
export OPERATOR_TOKEN='operator-access-token'

# NODE_ID is an existing inventory node ID, not an arbitrary claimed hostname.
export NODE_ID='inventory-node-id'
curl --fail-with-body "$WINFIRE_URL/api/v1/ai/reporters" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" -H 'Content-Type: application/json' \
  --data "$(jq -n --arg node "$NODE_ID" \
    '{name:"Research workstation",coverage:"instrumented",nodeIds:[$node]}')"
```

Save the returned `reporter.id`. The returned `credential` is shown once; it is hashed in
WinFire and cannot be retrieved later. Set it in the reporter environment:

```bash
export WINFIRE_AI_URL="$WINFIRE_URL"
export WINFIRE_AI_CREDENTIAL='wfai_enrollment-credential'
export WINFIRE_AI_SPOOL="$HOME/.winfire/ai-spool"
```

Create a metadata event file **once**, then retry the same file and event ID after failures:

```bash
node --input-type=module -e '
import fs from "node:fs";
fs.writeFileSync("ai-batch.json",JSON.stringify({events:[{
 schemaVersion:1,eventId:crypto.randomUUID(),operation:"research",
 observedAt:new Date().toISOString(),provider:"local",model:"private-model",
 outcome:"success",inputTokens:120,outputTokens:80
}]}),{mode:0o600});'

curl --fail-with-body "$WINFIRE_AI_URL/api/v1/ai/usage:batch" \
  -H "Authorization: Bearer $WINFIRE_AI_CREDENTIAL" \
  -H 'Content-Type: application/json' --data-binary @ai-batch.json
```

Example response:

```json
{
  "schemaVersion": 1,
  "results": [{
    "eventId": "producer-stable-event-id",
    "status": "accepted",
    "receiptId": "durable-receipt-id",
    "usageId": "operation-record-id",
    "mapped": true
  }],
  "counts": {"accepted": 1, "duplicate": 0, "rejected": 0}
}
```

`accepted` and `duplicate` include the durable receipt. A duplicate returns the same receipt
and does not increment operation or token totals. A conflicting replay is `rejected` with
`conflicting_replay`. Keep retrying only unavailable/`retryable` results; fix schema/binding
errors rather than generating new IDs for the same operation. An HTTP 200 batch can contain
rejected events, so inspect every result. The batch's valid records remain durable even when
another record is rejected. Invalid batch shape, over 100 entries, and oversized bodies fail
at the request boundary.

### Contract and lifecycle

[OpenAPI](API_ROUTES.md#aiusageevent) publishes field types and bounds.

| Fields | Behavior |
|---|---|
| `schemaVersion`, `eventId`, `operation`, `observedAt` | Required; schema version is `1`; timezone required |
| `operationId`, `phase` | Optional lifecycle grouping; phases `start`, `end`, `complete` (default) |
| `nodeId` | Optional, constrained by enrollment bindings |
| `provider`, `model`, `responseModel`, `tool` | Bounded metadata identifiers; unknown values remain explicit |
| `sessionId`, `traceId`, `spanId`, `parentSpanId`, `requestId` | Correlation identifiers, not transcript/content |
| `processId`, `processGuid`, `processStartedAt` | Optional process evidence; lifetime distinguishes PID reuse |
| `startedAt`, `endedAt`, `durationMs` | Optional; end cannot precede start |
| `outcome`, `errorCode` | `success`, `failure`, `cancelled`, `incomplete`; bounded error code, never raw exception text |
| `hostname` | Hostname or HTTP(S) URL; only normalized hostname persists, without user info, path, query or fragment |
| `inputTokens`, `outputTokens` | Optional nonnegative integers; missing is unknown, not zero |
| `cost` | Optional `{amount:"0.001",currency:"USD",source:"reported"}`; exact decimal totals grouped by currency/source |
| `adapterVersion` | Version of the producer's mapping |

Known operations: `search`, `research`, `browse`, `model_request`, `tool_call`, `embedding`,
`other`. An unknown operation is stored as `other` with `original_operation` retained.
Unknown object properties and recognizable credential-shaped identifiers are rejected by the server; client helpers strip unapproved fields. Approved metadata identifiers must still never contain secrets.

A start and end with the same reporter/operation ID produce one operation, even when the end
arrives first. Each phase must have its own stable event ID. Identity fields cannot change
between phases; only a missing value can be supplied. A second terminal event is a phase
conflict. Metrics belong on terminal events, not starts. Parent sessions and child tool/model
spans use **different operation IDs** and the parent-span field; do not report the same model
metrics on both a session and its children. Token totals sum supplied metrics, not reconstructed
usage. Times may be at most five minutes in the future and must be inside configured retention.
The operation timeline uses its start when known, otherwise its completion/observation time.
An unfinished start remains `incomplete`; the server does not invent a completion.

Limits: 256 KiB/request, 100 events/batch, 120 reporting requests/minute/reporter plus a 600/minute pre-authentication IP limit, 100,000 queued source jobs, bounded strings and numeric fields.
Most metadata identifiers are 128 characters; event/operation/node identifiers are 160.
Overload returns 429/503 or per-event retryable rejection. Source trigger drops are visible
in health; new retained events also have a resumable cursor path. After drops, use **Reclassify
retained events** to revisit older updated sources whose jobs may have been dropped.

### Query, export, rotation and health

```bash
curl --get "$WINFIRE_URL/api/v1/ai/usage" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  --data-urlencode "nodeId=$NODE_ID" --data-urlencode 'limit=25' \
  --data-urlencode 'sort=time' --data-urlencode 'order=desc'

curl "$WINFIRE_URL/api/v1/nodes/$NODE_ID/ai-usage?limit=5" \
  -H "Authorization: Bearer $OPERATOR_TOKEN"
curl "$WINFIRE_URL/api/v1/ai/observations?category=suspected&limit=25" \
  -H "Authorization: Bearer $OPERATOR_TOKEN"
curl "$WINFIRE_URL/api/v1/ai/usage/export?provider=local" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" --output ai-usage-export.json
curl "$WINFIRE_URL/api/v1/ai/health" -H "Authorization: Bearer $OPERATOR_TOKEN"
curl -X POST "$WINFIRE_URL/api/v1/ai/reporters/$REPORTER_ID/rotate" \
  -H "Authorization: Bearer $OPERATOR_TOKEN"
curl -X POST "$WINFIRE_URL/api/v1/ai/reporters/$REPORTER_ID/revoke" \
  -H "Authorization: Bearer $OPERATOR_TOKEN"
```

List/summary/export share filters: `q`, `nodeId`, `groupId`, `actorId`, `reporterId`, `provider`,
`model`, `operation`, `tool`, `from`, `to`, `outcome`, `category`, `confidence`, `mapped`.
Sorting: `time`, `node`, `provider`, `operation`, `outcome`, `model`, `reporter`, `hostname`,
with `order=asc|desc`; page size defaults to 25 and caps at 100. Exports cap at 10,000 matches;
narrow filters for larger datasets. An observation cannot satisfy a reported-only field such
as `model` or `actorId`: that filter returns no observations instead of guessing identity.
Reporter/catalog lists support `q`, `page`, `limit`, `sort`, `order`; their default is also 25.

Rotation invalidates the prior enrollment credential immediately while retaining the reporter
ID and idempotency history. It does not rotate the identity provider's OAuth credentials.
Revocation blocks **both** REST and OAuth ingestion immediately, including previously issued JWTs.

## 3. Remote MCP with a maintained OAuth provider

The endpoint is **`https://winfire.example.com/mcp/ai-usage`**, outside `/api/v1`. It exposes
only `report_ai_usage` and `report_ai_usage_batch`. Both write metadata through the same domain
service as REST and return the same durable receipt contract. Tool schemas declare writes,
idempotency and no arbitrary execution. There are no fleet-read or firewall-control tools.

Pinned runtime: `@modelcontextprotocol/server` / `node` / `client` **2.1.0**, Express integration
**2.0.1**, `jose` **6.2.12**. Current protocol **2026-07-28** and the SDK's legacy stateless
Streamable HTTP negotiation are exercised by the independent client tests. Unsupported
protocol revisions receive a protocol error. Classic HTTP+SSE transport is not provided.

Set on the API server, then restart it:

```dotenv
AI_OAUTH_ISSUER=https://identity.example.com/realms/winfire
AI_MCP_RESOURCE_URL=https://winfire.example.com/mcp/ai-usage
# Optional exact browser origins, comma separated; no wildcard.
AI_MCP_ALLOWED_ORIGINS=https://approved-agent.example.com
```

The public resource URL must use the exact endpoint path, without credentials/query/fragment.
HTTPS, exact Host and Origin validation apply. Use native API TLS or a trusted reverse proxy
with the application's existing trusted-proxy setting. Do not trust forwarded headers from
arbitrary clients. Cross-origin browser clients also need the origin in `CORS_ORIGIN`.
Loopback HTTP is permitted only by the test harness for remote MCP, not production.

### Keycloak configuration example

WinFire is the **resource server**, not a new authorization server. Use an existing maintained
OIDC provider such as Keycloak. Its discovery must expose the exact issuer, HTTPS JWKS,
authorization and token endpoints. WinFire validates RS256/ES256 access tokens, expiration,
issuer, audience, scope, subject and authorized client identity. Opaque access tokens and
provider API keys are not accepted.

1. Create a dedicated realm/client for this integration. Create a client scope named
   `ai:report` and include it in access-token scope.
2. Add an audience mapper with **Included Custom Audience** equal to the full
   `AI_MCP_RESOURCE_URL`; include it in access tokens. Give this client only the AI scope.
   Providers must issue the exact configured resource audience; an unrelated generic API
   audience or a client ID as audience will be rejected.
3. For interactive desktop/browser clients, register exact redirect URIs, enable the standard
   authorization-code flow, and require **PKCE S256**. Disable password/implicit grants.
   The MCP client handles authorization redirects and token refresh using the provider; WinFire
   does not collect the user's provider password or implement a token endpoint.
4. For unattended agents, use a confidential client with a service account and client-credentials
   grant. Store that client's secret/certificate in the agent's credential store. Use a short
   access-token lifetime and request `ai:report`. The provider returns `sub` and `azp` or
   `client_id`; bind all three of issuer, subject and client ID to the WinFire reporter.
5. In **Administration → AI usage → reporter → Edit bindings**, enter that exact OAuth binding
   and authorize the intended node(s). A signed token with no active matching binding still fails.

Client registration is performed at the provider. Clients that only support dynamic registration
must use a compatible provider registration configuration; the WinFire resource server does not
offer unrestricted dynamic registration. Configure an audience mapper when the provider uses
scopes/mappers rather than the OAuth `resource` parameter. Do not forward an OpenAI/Anthropic
provider token to WinFire. See [Keycloak service accounts, audience mappers and PKCE](https://www.keycloak.org/docs/latest/server_admin/).

Protected-resource discovery:

```bash
curl "$WINFIRE_URL/.well-known/oauth-protected-resource/mcp/ai-usage"
```

The unauthenticated endpoint returns a 401 `WWW-Authenticate` challenge pointing to that metadata.
Metadata advertises the authorization server and `ai:report`. With no provider configured, remote
MCP returns 503 with a configuration explanation; REST/stdio reporting remains available.

A standard remote-client entry uses its existing OAuth support, for example Claude Code:

```json
{
  "mcpServers": {
    "winfire-ai-usage": {
      "type": "http",
      "url": "https://winfire.example.com/mcp/ai-usage"
    }
  }
}
```

Provider registration/redirect settings must match that client's documented OAuth flow. For a
pre-provisioned unattended token, the official SDK accepts a token provider:

```js
import {Client, StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
const client = new Client({name:'research-worker', version:'1'}, {
  versionNegotiation: {mode: {pin:'2026-07-28'}}
});
await client.connect(new StreamableHTTPClientTransport(
  new URL(process.env.WINFIRE_AI_MCP_URL),
  {authProvider: {token: async () => process.env.WINFIRE_AI_OAUTH_TOKEN}}
));
// A production token provider should refresh through its maintained OAuth client/provider.
const result = await client.callTool({name:'report_ai_usage', arguments:{
  schemaVersion:1, eventId:crypto.randomUUID(), operation:'research',
  observedAt:new Date().toISOString(), outcome:'success', provider:'local'
}});
console.log(result.structuredContent); // receipts only
await client.close();
```

### Local stdio configuration

For clients without remote OAuth support, launch the adapter locally with a separately enrolled
reporter credential. Install dependencies in this repository first. Use absolute paths and set
the variables in the launching environment/credential manager; do not commit a real secret into
an MCP JSON file.

```json
{
  "mcpServers": {
    "winfire-ai-usage": {
      "command": "node",
      "args": ["/opt/winfire/integrations/ai/stdio.mjs"],
      "env": {
        "WINFIRE_AI_URL": "https://winfire.example.com",
        "WINFIRE_AI_CREDENTIAL": "replace-from-credential-store",
        "WINFIRE_AI_SPOOL": "/home/agent/.winfire/ai-spool"
      }
    }
  }
}
```

The adapter never imports/opens the inventory database. It returns only receipts for the
requested tool call. If the API is unavailable, valid reports are buffered and the tool returns
an error explicitly saying no durable receipt was confirmed. Retry with the same IDs or run
`node integrations/ai/flush.mjs`. Reporting tools must not recursively report themselves.

## 4. Reliable application integrations

### JavaScript

```js
import {AiReporter} from './integrations/ai/reporter.mjs';
const reporter = new AiReporter(); // reads WINFIRE_AI_* environment
const result = await reporter.track({operation:'research', provider:'local'}, async () => {
  return {completed:true}; // actual agent work; result content is never reported
});
// Run flushing separately from latency-sensitive agent work.
await reporter.flush();
await reporter.heartbeat();
```

`record()` writes approved metadata to a private spool and returns its stable event ID or null.
`track()` records success, failure or AbortError cancellation without storing exception text.
`node integrations/ai/example.mjs` provides a deterministic local example flow.

### Python (standard library only)

```python
import sys
sys.path.insert(0, '/opt/winfire/integrations/ai')
from reporter import AiReporter
reporter = AiReporter()
with reporter.track(operation='research', provider='local'):
    result = {'completed': True}
reporter.flush()
reporter.heartbeat()
```

Both helpers retain stable metadata files across restart, default to 1,000 queued events (maximum
10,000), use private directory/file permissions, reject redirects, and back off up to five minutes.
`flush()` sends at most 100 events, with a five-second network timeout; keep it in a background
worker/timer or schedule `flush.mjs`. There is no automatic background thread on import. Heartbeat
reports queue, drops and schema mismatch. Work wrappers do not wait for network delivery; disk
write failures increment drop health rather than replacing the user's operation result/error.
Initialize configuration separately so an invalid URL or unwritable initial spool can be noticed.

### Claude Code completion hook

The hook maps `PostToolUse` and `PostToolUseFailure` to metadata-only search/browse/tool reports,
including `is_interrupt` cancellation. It never copies tool input/output, transcript paths or
error text. Model requests outside these hooks are **not** covered. Stable session/tool-use IDs
prevent duplicate operation records; a bounded private timestamp cache stabilizes hook retries.

```json
{
  "hooks": {
    "PostToolUse": [{"matcher":".*","hooks":[{
      "type":"command","command":"node /opt/winfire/integrations/ai/claude-hook.mjs"
    }]}],
    "PostToolUseFailure": [{"matcher":".*","hooks":[{
      "type":"command","command":"node /opt/winfire/integrations/ai/claude-hook.mjs"
    }]}]
  }
}
```

The hook only queues; schedule `node /opt/winfire/integrations/ai/flush.mjs` with the same environment
and spool. It exits quietly on telemetry failure. The fixture tests completion, failure,
interruption, stable IDs and recursive-call suppression against the
[official Claude hook fields](https://code.claude.com/docs/en/hooks).

### OpenTelemetry GenAI adapter

`integrations/ai/otel.mjs` exports `fromGenAiSpan()` for a normalized span and `fromOtlp()` for
OTLP/JSON `resourceSpans[].scopeSpans[].spans[]`. Import a saved JSON export with:

```bash
node integrations/ai/otel-import.mjs < genai-spans.json
node integrations/ai/flush.mjs
```

Mapping is pinned as **`otel-genai-2026-09-24-v1`**. It uses `gen_ai.operation.name`, provider,
request/response model, tool name, server address and total input/output tokens, plus trace/span
and parent IDs. Nanosecond OTLP timestamps become UTC milliseconds. Cache/read/reasoning subsets
are not added a second time. Span prompts/messages are ignored. The importer caps input at 4 MiB
and 1,000 spans; split larger exports upstream. No public OTLP receiver or auto-instrumentation
of arbitrary applications is installed. Sampled/exported spans are partial coverage; upstream
instrumentation must produce the documented GenAI fields. Review mapping changes against
[OpenTelemetry GenAI conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/).

## 5. Network evidence, catalog and correlation

Sources:

- Windows allowed/blocked firewall events, including compacted event patterns.
- Existing enrolled browser events with a directly observed hostname; domain-only records do
  not invent an IP association.
- Shared Internet PTR cache. PTR-only evidence is **suspected / low confidence** and does not
  prove which hostname an application requested.
- Optional reporter-scoped DNS answers from **Microsoft-Windows-Sysmon / Operational**, with
  time, answer IPs and optional PID/GUID/process-start information.

Optional DNS ingestion (Sysmon Event 22 is a source; WinFire does not enable Sysmon automatically):

```bash
curl --fail-with-body "$WINFIRE_URL/api/v1/ai/dns" \
 -H "Authorization: Bearer $WINFIRE_AI_CREDENTIAL" -H 'Content-Type: application/json' \
 --data '{"schemaVersion":1,"eventId":"sysmon-stable-event-id","hostname":"api.anthropic.com",
 "answers":["203.0.113.21"],"observedAt":"2026-09-24T12:00:00Z","ttlSeconds":60,
 "processId":123,"provider":"Microsoft-Windows-Sysmon",
 "channel":"Microsoft-Windows-Sysmon/Operational"}'
```

Replace the fixture timestamp with the actual event time and addresses with actual DNS answers.
Answers are usable only within the smaller of their supplied TTL and configured DNS window.
When TTL is absent, the configured window is an application evidence bound, not authoritative DNS
TTL. Stale answers do not identify traffic; multiple names on a shared IP remain ambiguous.
Missing DNS coverage is shown in health/evidence. DNS answers alone are not AI usage records.

| Category | Interpretation |
|---|---|
| Reported | Explicit metadata from an authorized reporter |
| Observed | Dedicated service contact supported by a browser hostname or contemporaneous scoped DNS |
| Suspected | PTR/process hint, uncertain requested host or incomplete attribution |
| Supporting | Provider authentication, telemetry, update or shared service infrastructure |

The versioned catalog seeds OpenAI/ChatGPT, Anthropic/Claude, GitHub Copilot, Gemini, Microsoft
Copilot/Azure AI and six documented regional Bedrock runtime hosts. Every row links its official
source and review date. Other regions/private services can be added after review. A domain match
establishes service contact, not the API method/model operation; mixed-purpose API hosts remain
mixed-purpose evidence. Public-suffix wildcard rules are rejected using `tldts`/the maintained
Public Suffix List. Exact/more-specific matches take precedence; disabling a specific match
shadows a broader suffix rule. Built-in defaults remain enabled until explicitly disabled.

Correlation requires a compatible mapped node and bounded event time. Explicit trace/request
IDs can create a unique link; multiple matches remain candidates. PID/GUID/start plus hostname
can create candidates; node/host/time alone remains a candidate with process identity unknown, with missing process lifetime explicitly labeled. Conflicting process
lifetimes/GUIDs are rejected. A central firewall/router/switch collector is retained separately
from unknown workload identity; its traffic is not automatically assigned to its own workload.
Parallel sessions, reused connections, HTTP/2 and QUIC do not create extra reported operations.
Connections and operation metrics stay in separate tables and totals. Token/cost values are never
inferred from packet counts, IPs, DNS or provider contact.

Source exclusions are respected on classification/reclassification. Existing original events
remain in their original views. Enrichment retains the original classification and versioned
rule evidence. Expired original transactions are labeled in details; AI evidence follows its own
configured retention. Disabled/unmatched rules remove current matches during bounded reprocessing.
Retained backfill can lag during large migrations; inspect health before treating a zero as no
activity. The catalog/worker is intentionally bounded, not a packet capture or TLS decryption system.

## 6. Operator workflow and troubleshooting

**Visibility → AI Usage** has Reported usage, Observed AI traffic and Reporters / coverage tabs.
Search/filter/sort/paginate on the API; default 25 rows. **More filters** exposes actor, reporter,
group, model, operation/tool and evidence criteria. Deep links retain applied filters. Click a
row or View details to open a floating evidence/receipt dialog. Node details include the same
node-scoped totals and recent timelines, with links to the fleet view. Unknown metrics/identity
are explicit; no policy is automatically deployed from a suspected provider.

| Symptom | Checks |
|---|---|
| Remote MCP 503 | Configure issuer/resource URL; verify HTTPS discovery and JWKS access |
| MCP 401 | Token expiry/issuer/audience/client/subject binding; active reporter; use access token, not API key |
| MCP 403 | `ai:report` scope, exact Host/Origin and authorized node |
| REST 401 | Use `wfai_` reporter credential; operator tokens cannot report; rotate/revoke state |
| Rejected record | Inspect receipt code: invalid schema, node authorization, conflicting replay/phase, time bounds |
| No observed traffic | Worker backlog, retained-event cursors, host evidence, catalog match and DNS coverage |
| Too many unknown actors | Actor is not inferred from a connection; bind only an independently known identity |
| Stale reporter | Check its scheduled flush/heartbeat and local queue/drops; heartbeat does not prove complete reporting |
| Usage appears twice | Reuse IDs for retry; use one instrumenter per operation; do not copy parent metrics to child spans |
| No local-model traffic | Expected: local operations can have reports without Internet observations |
| Changes not immediately visible | Refresh the app/table and allow bounded backfill/enrichment to complete |

Retention deletes at most 1,000 expired rows per metadata table every two minutes; manual purge
runs another bounded batch. Foreign-key cascades remove operation/observation associations.
Catalog version history and administrative audit records follow their configuration/audit
lifecycle, not usage-event retention. Reporter counters are lifetime delivery counters and may
exceed retained usage counts. Receipt retention preserves recent retry identity; events outside
retention are rejected instead of resurrected. Turning collection off does not turn retention off.

## 7. Validation and limits

Release checks (2026-09-24): isolated migration and API tests, real official SDK HTTP (current
2026-07-28 and default legacy negotiation) and stdio clients, OAuth discovery/JWKS audience/scope/
origin/revocation failures, accepted/replayed/conflicting operations, out-of-order lifecycles,
process restart receipts, redaction, Python/JS offline adapters, hook and OTLP fixtures, DNS/shared-IP/
stale-answer/blocked traffic, catalog reclassification, retention and node/fleet count parity.

A representative isolated SQLite run with 50,000 operations and 50,000 source events returned a
25-row filtered page at page 900 in ~61 ms and processed a bounded 100-row worker pass in ~27 ms
on the development host (a repeat measured ~67 ms / ~27 ms). These are measurements, not throughput guarantees. Browser checks use
an isolated API with representative records: enrollment/one-time credential, filter/search,
pagination, details/Escape, settings switches, enterprise light/dark and horizontal overflow.

No production identity provider, live paid AI request, or real private prompt was required or
used by these checks. OAuth was validated against an isolated signed-JWT discovery/JWKS issuer;
configure and test your own maintained provider and client registration before remote deployment.
The browser extension and DNS collector must already supply their underlying source events.
See [research decisions and acceptance matrix](AI_USAGE_RESEARCH.md) for evidence boundaries.

Repeatable checks: `npm test` (277 passing tests at delivery), `npm run test:ai`,
`npm run test:ai:scale`, and `npm run test:ai:ui`. The UI script uses a disposable local
database and its own Playwright CLI session; set `PLAYWRIGHT_CLI_WRAPPER` if your wrapper
is installed elsewhere. It checks 1440, 760 and 390 px layouts, including actual scroll movement.
