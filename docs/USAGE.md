# Operator guide

## Appearance

Enterprise light and Enterprise dark use the same navigation, layouts, tables, and forms. The sun/moon button in the top bar switches the color palette for this browser.

Under **Administration → Security → Appearance**, choose an account theme and save it. **Follow system** tracks the operating system's light/dark setting, including changes while the app is open. **This browser → Use account theme** clears the local override; otherwise the browser choice takes precedence over the saved account theme. Browser overrides synchronize across tabs. Older Hacker/Dark preferences now open Enterprise dark.

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

## SNMP MIB library

Open **Administration → Discovery → SNMP → MIB library**. Built-in profiles collect additional interface, hardware, host-resource, routing, neighbor, TCP, VLAN-forwarding and LLDP evidence. Import one or more vendor ASN.1 MIBs with their dependencies, preview, then import. Use **Details / Configure** to select readable objects and set sysObjectID prefixes or sysDescr phrases; use switches to disable a source or object.

The **Modules** tab configures collection. **Source files** provides search, status filters and downloads of original files, including alternate versions and files needing attention. Uploads use multipart form data; source files live on the API server under `SNMP_MIB_LIBRARY_DIR` (default `DATA_DIR/snmp-mibs`). Total library capacity is limited by available disk space. Full [Cisco](SNMP_LIBRARY.md#source-files-and-full-cisco-catalog) and [LibreNMS](SNMP_LIBRARY.md#librenms-catalog-and-vendor-folders) importers run on the server. LibreNMS vendor subfolders remain part of each source filename and can be searched. Back up the source directory along with the database.

Each successful identity poll matches enabled profiles and persists links to the node. Later polls recognize those links, recheck identity, and discover newly imported matching sources. The node's details show **SNMP library and collected data**, match evidence, collection status and searchable paginated values. Unsupported MIBs do not make a successfully authenticated device unreachable. [Full workflow, supported MIBs and API examples](SNMP_LIBRARY.md).

## Static and dynamic node groups

Use **Node groups → Add node group** and select Static or Dynamic. Static groups have manually selected members. Dynamic groups match node attributes (hostname/name, FQDN, exact IP or CIDR) with all/any conditions; enable rules with the switch. Refresh now or configure the interval in Administration. Membership changes are audited. Direct member edits are blocked while a group's dynamic rules own membership.

Groups can scope policies and credentials. Inspect group membership before deploying a group-wide change, especially when changing a dynamic rule.

## Policies and learning

1. Review new-host training and its duration/progressive schedule in Administration.
2. Collect representative traffic; inspect the generated learning proposal and evidence rather than assuming every observed flow is wanted.
3. Build/edit policies using the **Visual editor** and **Form editor** tabs in Policy Studio. Resolve overlaps/conflicts and review compiled rules/version differences.
4. Verify, assign to the intended node or group, and use **Sync policies**. Learning sessions own their generated policies until the workflow permits review/apply.
5. Inspect apply runs and verification results per host. A queued deployment is not a confirmed applied policy. Use versions/recall and the normal sync workflow for rollback.

### Policy Studio authoring

Select a policy in the library. Both editor tabs use the same graph and remain visible for learning/read-only policies. The rule palette includes Allow, Reject, Program, Port group, Address group, Profile scope, Schedule and MFA gate nodes. Click a graph node or a Form editor row to inspect/edit its fields, connected scopes and last compiled rule. **Apply to draft** accepts the dialog changes; **Cancel** leaves the graph unchanged.

Connect a scope's right handle to a rule's left handle, or use **Connect nodes** with the source/target selectors. Scope chains are supported. Explicit rule fields take precedence over inherited values. Port groups supply local ports for inbound rules and remote ports for outbound rules. Address/profile scopes supply remote addresses/profiles; a rule can inherit one schedule. Cycles, duplicate connections and invalid fields are rejected. MFA gates remain standalone metadata and do not turn an ordinary connection into MFA enforcement.

Use **Zoom in/out**, **Fit view**, **Arrange nodes**, **Undo/Redo**, and the expandable Connections list. Click an edge for connection details/removal. Deleting a node removes its incident connections; Undo restores them. Rule details support duplication and deletion. Browser drafts are scoped to the operator and policy; a restored draft is labeled. **Discard draft** returns to the latest saved version. Saving a stale version is rejected instead of overwriting another operator's changes.

The API validates and compiles draft changes before saving. The compiled output shows the draft's effective rules, inherited scope, conflicts and warnings. **Save version** stores a version without deploying it. **Assign** controls node/group/global targets; **Apply** applies the saved version to assigned nodes after confirmation, while the top navigation's **Sync policies** remains available for staged changes. **History** compares or recalls saved versions. Active learning policies remain read-only in both tabs, with clickable rule/evidence details.

API clients can preview and save the same graph:

```bash
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @draft.json \
  "$BASE/api/v1/policies/$POLICY_ID/preview"
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @version.json \
  "$BASE/api/v1/policies/$POLICY_ID/versions"
```

`draft.json` contains `{ "graph": { "nodes": [...], "edges": [...] } }`. `version.json` adds `comment` and `baseVersionId` (the version originally loaded, or `null` for the first save). Preview returns `rules`, `mfaGates`, `warnings`, `conflicts`, `managementIssue` and `canSave`; it creates no version and changes no firewall. The API enforces policy permissions and learning ownership independently of the UI.

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

## Internet connections outside LAN

**Internet** has separate **Browser activity**, **Internet connections**, **Browser devices**, and **Internet Policy Studio** tabs. The connections table uses configured IPv4/IPv6 local CIDRs, server-side filters/sorting and 25-row pagination. Private peers outside those CIDRs are included; special non-unicast peers are excluded. CIDR edits rebuild retained classifications in the background and expose pending status. Reverse-DNS names are PTR evidence, not confirmed website addresses. No external peer is added to inventory. See the [complete workflow, DNS configuration and curl examples](INTERNET_CONNECTIONS.md).

## AI Usage visibility

Open **Visibility → AI Usage** for reported operations, observed/suspected AI traffic and reporter coverage. Administration → AI usage manages reporters, provider rules and retention. Node details link to scoped activity. [The detailed guide](AI_USAGE.md) covers client configuration, interpretation, filters and troubleshooting. Connections do not imply completed operations or token usage.
