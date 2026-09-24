# Internet connections outside the configured LAN

## Configure and use

1. In **Administration → Server config**, save **Local asset CIDRs**, one IPv4 or IPv6 CIDR per line. Host bits and overlapping ranges are supported. IPv4-mapped IPv6 addresses normalize to IPv4. Malformed ranges are rejected; `/0` covers that entire address family.
2. Open **Internet → Internet connections** (`/internet?tab=connections`). Browser activity remains the default tab; Browser devices and Internet Policy Studio have independent tabs at `?tab=devices` and `?tab=policies`.
3. Filter by reporting node/group, time, peer IP or subnet, PTR hostname, program, protocol, destination port, action, direction or DNS state. Search, sorting, counts and pagination run on the API. The default is outbound observations and 25 rows.
4. Click an observation for its full retained firewall event, endpoint attribution, original/current boundary revisions, DNS evidence and links to Activities and Mapping. Authorized administrators can stage allow/reject firewall rules or ignore matching traffic. Rule creation uses the existing policy authorization, conflict checks and learning-state restrictions. Saving a rule does not immediately sync it to a host.
5. Click the DNS-state button for PTR history. Editors/admins can queue a refresh. Exports use the same applied filters and completed scope revision and contain at most 10,000 records; narrow filters for larger datasets.

## What qualifies

An eligible unicast peer **outside configured local CIDRs** is included, even if it is in an RFC1918 private network or CGNAT range. A configured public subnet is local. The address-category column remains visible; outside LAN does not assert public routability. Loopback, link-local, multicast, broadcast, unspecified, invalid and reserved non-unicast addresses are excluded from the Internet tab and retain their existing event history.

With no local ranges, Internet shows **Configure local network CIDRs** and does not classify all hosts as Internet. Inventory retains its existing unrestricted behavior until a boundary is supplied. If only one address family is configured, the view explicitly warns that eligible peers in the other family are outside LAN. External peers never become assets as a result of this feature or its DNS lookups. Discovery registration and inventory filtering use the shared CIDR service; active CIDR scan target expansion remains IPv4-only.

Allowed WFP events are **allowed observations**, not proof that a connection succeeded or a session completed. Blocked events are **blocked attempts**. The reporting collector and actual local endpoint are separate fields: forwarded router traffic is not automatically attributed to the router as its originating process. Legacy Windows inbound layouts are corrected using the reporting node address. Roaming/direction-derived and ambiguous ownership are labeled. Quick allow/reject actions are unavailable for forwarded, ambiguous and corrected layouts where the existing rule endpoint cannot safely reuse the tuple.

This view indexes retained `log_events`, resolving compacted fields through `event_patterns`. It does not duplicate observations into browser navigation data or invent firewall event IDs for SNMP state snapshots. SNMP observations remain in Mapping and node facts. Existing process exclusions and traffic-ignore rules apply to connection lists, detail reads, counts and exports. The original event ID remains available through `GET /logs/search?id=...`.

## Backfill, changes and retention

A durable queue captures new or corrected log events. A bounded background worker backfills pre-existing retained events in batches of 1,000. Event/revision keys make replay idempotent. Each CIDR edit creates a versioned boundary and a new bounded reclassification pass; its cursor survives restart. Internet lists and Mapping external filters use the **same completed boundary** until the next revision is ready, avoiding mixed old/new counts. Internet responses expose current/desired revisions, pending state and cursor/high-water progress. Inventory uses the newly saved boundary immediately.

The original classification revision/scope stays with an observation while its current projection is rebuilt. No Activities or Mapping history is deleted by a scope change. Log retention removes corresponding connection projections by foreign-key cascade. Old projection revisions are removed in bounded batches after publication. Peer records without retained observations and DNS history expire under the peer-retention policy. Back up the application database as usual; this feature requires no separate database or service.

## PTR evidence and caching

A dedicated Node.js [DNS resolver](https://nodejs.org/api/dns.html#class-dnspromisesresolver) performs asynchronous IPv4/IPv6 reverse lookups after a peer is retained. It does not fetch a URL, perform a browser request, or add an inventory node. IP plus resolver context identifies the cache entry. Repeated observations share one pending lookup; leased jobs recover after restart.

All PTR names, lookup status, check time, last success and history are retained. PTR names are **reverse-DNS evidence**, not a hostname proven to have been requested by a browser. Shared hosting/CDNs, proxies and absent PTRs can limit interpretation. Browser activity remains its own evidence source; firewall records currently contain no observed browser/DNS hostname association, so `observedNames` is empty rather than guessed.

Defaults are 24 hours for successful answers and 1 hour for missing answers. These are application cache policies, **not authoritative DNS TTLs**. Transient failures keep the last successful names marked stale and retry after 1, 2 and 4 minutes, then the negative-cache interval. Definitive missing answers clear current names while retaining history. Manual refresh is coalesced, requires editor permission, and is limited to 20 requests/minute per client and one completed lookup/minute per peer.

| Environment variable | Default | Meaning |
|---|---|---|
| `INTERNET_DNS_SERVERS` | system DNS | Comma-separated resolver addresses accepted by Node `Resolver.setServers`. Changing this creates a distinct resolver context for newly indexed peers. |
| `INTERNET_DNS_POSITIVE_HOURS` | 24 | Successful-answer refresh policy, 1–8760 hours. |
| `INTERNET_DNS_NEGATIVE_HOURS` | 1 | Missing-answer/error cache policy, 1–168 hours. |
| `INTERNET_DNS_TIMEOUT_MS` | 3000 | Per-lookup deadline, 100–10000 ms. |
| `INTERNET_DNS_CONCURRENCY` | 4 | Concurrent lookups, 1–16; up to 25 jobs per 10-second sweep. |
| `INTERNET_PEER_RETENTION_DAYS` | 90 | Unreferenced peer and DNS-history retention, 1–3650 days. Referenced peers remain available. |

DNS failure does not block ingestion or indexing. Resolver settings are server configuration; no credentials are required.

## REST API and curl

All reads require auditor or higher permissions; DNS refresh requires editor or higher. Existing firewall rule/ignore actions require admin permission. Set `BASE` to the origin and `TOKEN` to an operator access token.

```bash
# Outbound is the default; use direction=all for the complete eligible view.
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/internet/connections?direction=out&limit=25&page=1&sort=time&order=desc"

# Private address ranges outside LAN are eligible too. URL-encode filter values.
curl --fail-with-body -G -H "Authorization: Bearer $TOKEN" \
  --data-urlencode 'ip=10.9.0.0/16' --data-urlencode 'action=block' \
  "$BASE/api/v1/internet/connections"

curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/internet/connections/summary?direction=all"
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/internet/connections/$EVENT_ID"
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/logs/search?id=$EVENT_ID&hideLoopback=false"
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/internet/peers/$PEER_ID"
curl --fail-with-body -X POST -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/internet/peers/$PEER_ID/resolve"
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/internet/connections/export?direction=out&action=block" -o internet-connections.json
```

List parameters: `q`, `nodeId`, `groupId`, `ip` (IP or CIDR), `hostname`, `program`, `protocol`, `port`, `direction` (`out`, `in`, `unknown`, `all`), `action` (`allow`, `block`), `dnsState` (`pending`, `resolved`, `not-found`, `error`, `stale`), `from`/`to` (ISO time with offset), `page`, `limit` (1–100, default 25), `sort` (`time`, `node`, `peer`, `hostname`, `program`, `protocol`, `port`, `action`, `direction`) and `order` (`asc`, `desc`). Summary and export accept the same filters.

List returns `items`, `total`, `page`, `limit`, `pages` and `summary`. Summary contains matching `events`, unique `peers`, `allowed`, `blocked` and `scope`. Detail includes the original `event`, peer evidence, `ruleEligible` and cross-view references. Refresh responds `202` after enqueueing; it does not wait for DNS. Invalid filters return `400`, missing/out-of-scope/excluded records return `404`, and throttled refreshes return `429`.
