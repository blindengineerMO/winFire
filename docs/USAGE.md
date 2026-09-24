# Operator guide

## Start with the inventory boundary

Set **Administration → Server config → Local asset CIDRs** to the networks you own. The monitored-asset list and dashboard use that scope; external peers remain visible as traffic endpoints in events and mapping. Saving no CIDRs leaves the older inventory behavior unrestricted. DHCP import deliberately requires a configured boundary.

Scope affects inventory visibility, not the meaning of a firewall event. Do not delete or discard external events merely to keep inventory clean. CIDR discovery targets and local-asset scope are separate settings: the former selects what to probe; the latter selects which addresses belong in monitored inventory.

## Credentials and discovery

Store credentials under **Administration → Credentials**, then bind them in **Edit node** or supported group/discovery settings. Secrets are write-only and encrypted. Use separate credentials for directory reads, Windows administration, SSH, ESXi, and SNMP. Credential priority controls candidate ordering; resource grants control who can use/edit them.

**Test before onboarding:** Windows and SSH credentials have a preflight action that authenticates against a host without committing a new asset. Existing bound credentials can also be tested against a node. Review the structured onboarding error (closed port, rejected credentials, WinRM listener, WMI/DCOM, Kerberos/SPN, or unknown) rather than treating a TCP response as successful authentication. Credential health notices correlate repeated failures across hosts using the same credential, helping distinguish a rotated credential from one unreachable machine.

| Discovery source | Configuration and evidence |
|---|---|
| CIDR probes | Enter IPv4 CIDRs; scan uses ICMP then bounded ARP/TCP fallbacks. TTL supplies a weak Windows/Linux/other family hint only. |
| Recurring scans | Name, CIDRs, interval 5–10,080 minutes, enabled switch. Run now/pause/delete controls; each completed run compares new, dark and changed hosts with the prior run. |
| Infrastructure / ESXi | API fingerprints take priority over TTL. Select VMware ESXi node type, API management and ESXi vault credential to collect host/version and VM inventory. |
| SNMP polling | Choose target and SNMP v2c/v3 credential. Successful authenticated polling collects available identity, ARP, routes, TCP states, bridge MAC/ports and vendor-specific facts. Device MIB support determines which tables exist. |
| Linux | Configure the default SSH discovery credential and host-key policy. Strong Linux facts replace weak TTL hints once SSH succeeds. A stored fingerprint is preferable to accepting an unverified host key. |
| ARP / Other | Review candidates observed by managed collectors. Processing candidates invokes the normal discovery path and may contact hosts; this differs from passive DHCP import. |
| DHCP leases | Import current Windows DHCP exports without a scan. Preview MAC/IP matches, conflicts and eligibility; see [DHCP import](DHCP_IMPORT.md). |
| Directory | Configure LDAPS URL, search base, bind and host-management credentials, test, then synchronize. Directory identity is correlated with existing nodes. |

TTL is not an OS guarantee: hops decrement it and multiple kernels share defaults. SNMP system strings, authenticated host facts and hypervisor APIs take precedence. Device classification evidence and passive traffic hints are exposed separately so operators can see why an identity was suggested.

## Monitored assets and triage

The Assets tab uses API-side search/filter/sort and defaults to 25 rows. Managed/learning assets are prioritized. OS name and version are separate lines; long values are bounded visually. Select a node for full facts, classification evidence, DHCP lease evidence, network interfaces, firewall rules and management verification.

**Mode, reachability and verification are different:** an unknown discovered node remains unmanaged; SNMP responsiveness does not imply Windows enforcement; ESXi API management collects infrastructure facts without treating the host as a Windows firewall. A successful authenticated SNMP poll establishes SNMP verification. A DHCP lease alone leaves status unknown and verification unchecked.

Edit node chooses the device type, management method and credentials in one place. ESXi uses API credentials; Linux uses SSH; network devices can use SNMP. VM correlation adds **Virtual Machine** beneath the hostname and exposes hypervisor/guest details. Correlation depends on reported guest names/addresses and available inventory evidence; absent guest tools or stale addresses can limit it.

The **Unmanaged assets** tab is a local inventory triage queue after a configurable grace period. Search/filter the queue, flag a record, exclude it from triage, restore it, or assign credentials and retry. Bulk triage acts on the selected IDs and returns per-node results; partial failures remain visible. Excluding a triage record does not mean its traffic should disappear from visibility.

## Static and dynamic node groups

Use **Node groups → Add node group** and select Static or Dynamic. Static groups have manually selected members. Dynamic groups match node attributes (hostname/name, FQDN, exact IP or CIDR) with all/any conditions; enable rules with the switch. Refresh now or configure the interval in Administration. Membership changes are audited. Direct member edits are blocked while a group's dynamic rules own membership.

Groups can scope policies and credentials. Inspect group membership before deploying a group-wide change, especially when changing a dynamic rule.

## Policies and learning

1. Review new-host training and its duration/progressive schedule in Administration.
2. Collect representative traffic; inspect the generated learning proposal and evidence rather than assuming every observed flow is wanted.
3. Build/edit policies in visual Policy Studio or the classic editor. Resolve overlaps/conflicts and review compiled rules/version differences.
4. Verify, assign to the intended node or group, and use **Sync policies**. Learning sessions own their generated policies until the workflow permits review/apply.
5. Inspect apply runs and verification results per host. A queued deployment is not a confirmed applied policy. Use versions/recall and the normal sync workflow for rollback.

Break glass temporarily changes host firewall profile state and has an audited rollback session; use the dedicated workflow with a reason and bounded duration. It is separate from an MFA grant for a particular source/port.

## Firewall events and Accounts

**Activities (`/logs`)** contains Firewall events, Accounts, and Learning sessions tabs. Accounts contains logon/logoff activity; 4624 is Logon, 4634 Logoff. Use server-side date, node, action, source/destination, port, program, account and event filters. Paging defaults to 100 events. Click a transaction for complete details and applicable quick allow/deny/ignore actions; inspect the resulting rule before applying it.

Loopback hiding changes the view. Ingestion discard prevents storage. Traffic/process ignore settings and retroactive cleanup have different effects; choose intentionally. Configure named export destinations before exporting selected events. Retention and compaction run on the server, so totals may change as maintenance completes.

## Mapping and topology

Mapping separates **Connections**, **Topology**, **Most active nodes**, and **Neighbors**. The graph combines observed traffic with learned ARP/forwarding evidence. A link is an observation, not proof of a physical cable.

Filter by node, subnet, switch, time range and internal/external traffic classification. Subnet and switch filters must match the same endpoint; the other endpoint is retained to show boundary traffic. Switch scope correlates ARP and forwarding-table MACs, including inventory MACs and observations from other collectors. Graph matches are highlighted. A switch uplink may reveal remote MACs, so membership is not proof that a device is directly attached. Neighbor links use node/subnet/switch/time criteria; traffic-only class/external filters apply to flow edges.

Use **Rebuild map** to reconstruct stored aggregates from retained evidence after configuration/data changes, then Refresh. External peers do not need inventory records to appear. Empty maps can mean filters excluded all observations, collection is missing, or the API process lacks the current routes; check errors before rebuilding repeatedly.

## Classifier, directory, identity and administration

Built-in and IANA classifier rules are enabled unless explicitly disabled. Custom port/protocol and process rules provide environment-specific names; conflicting definitions are rejected. Use existing rules' edit/disable controls instead of duplicating a match.

Directory provides AD and local account inventory, membership/SID details, linked operators, logon history and controlled account actions. Account-control operations require their appropriate credential and audit reason. Identity segments and JIT grants are described in [JIT MFA](JIT_MFA.md).

Administration holds users/roles/teams, credentials, directory, discovery, training, logs/DNS/retention, classifier, branding, Entra, MFA prompt behavior, exports, security automation, RPC filters, agents and TLS. Boolean settings use switches. Environment-owned public URL/TLS/secret settings may override saved UI values; inspect the effective values and source reported by the API.

Browser Internet telemetry is a separate feature with extension enrollment, collection level and URL policy. See [enterprise Internet deployment](INTERNET_ENTERPRISE_DEPLOYMENT.md) for rollout details. It is navigation metadata, not packet capture or page-content inspection.

## Interface route map

| Route | View / access |
|---|---|
| `/` | Dashboard (signed in); there is no separate `/dashboard` route. |
| `/inventory` | Assets, node groups and unmanaged triage. |
| `/directory` | Directory and local account inventory. |
| `/policies` | Policy Studio and policy lifecycle. |
| `/reports` | Inventory, policy and verification reporting. |
| `/logs` | Activities: firewall events, Accounts and learning sessions. |
| `/internet` | Browser telemetry and Internet policies. |
| `/mapping` | Connections, topology, top talkers and neighbors. |
| `/identity` | Segments, portal access, grants and MFA identity workflows. |
| `/admin` | Administration and configuration. |
| `/login` | Operator sign-in. |
| `/accept-invite`, `/verify-email` | Token-linked account workflows. |
| `/enroll-authenticator` | AD authenticator enrollment. |
| `/tools` | Public tooling/download view; protected downloads enforce their own checks. |
| `/mfa/:promptId`, `/mfa/callback` | Public prompt and MFA callback views. |

UI routes are client-side views; API calls use `/api/v1`. A reverse proxy must route non-API navigation to the SPA while preserving `/api` errors/responses. There is no standalone `/activities` Vue route in the current application.
