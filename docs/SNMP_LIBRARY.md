# SNMP discovery and MIB library

## Operator workflow

1. Configure an SNMP v2c or v3 read-only credential in the vault. Assign it in Edit node, or create a target under **Administration → Discovery → SNMP → Polling targets**.
2. Open **MIB library** beside Polling targets. The library includes curated collection profiles; a device need not implement every profile. Search, source filtering, sorting and paging run on the API, default 25 rows.
3. Choose **Import MIBs**, select one or more plain text ASN.1 files (`.mib`, `.my`, `.txt`), and include required vendor dependencies. File order does not matter. Core SMIv1/v2 dependencies are bundled by the SNMP library. Standard collection profiles contain curated OIDs, not complete dependency MIB source files; import the full source when another vendor MIB imports it.
4. **Validate and preview** checks module structure, imported symbols, OID resolution, duplicates and dependency cycles. No device is contacted or configuration saved by preview. Import saves the batch atomically. Invalid or missing dependencies reject the batch with an actionable error.
5. **Details / Configure** lists resolved readable objects. Scalar objects use GET with `.0`; table columns use bounded GETNEXT/GETBULK walks. Switches select up to 64 objects per module. The first 64 readable objects are selected on initial import; review large modules to select the relevant measurements.
6. In the same dialog, review device matching. Vendor enterprise prefixes are inferred from module OIDs. A module without an inferred enterprise needs a sysObjectID prefix or sysDescr phrase before it can match. Dependency-only and notification-only MIBs can be imported but have no readable data to collect.
7. Run **Poll now** or wait for the existing scheduled node/target poll. The node's facts show **SNMP library and collected data**, including source, evidence, support status and searchable collected values.

The UI uses Multer multipart uploads to the API server. JSON imports remain compatible for small batches. Filenames are labels, not filesystem paths. No external compiler, executable, shell command, URL fetch, SNMP SET or trap listener is invoked. MIB descriptions and filenames are rendered as text. Source files live under `SNMP_MIB_LIBRARY_DIR` (default `DATA_DIR/snmp-mibs`) with content-addressed storage keys. SQLite stores metadata, configuration, source indexes and device links. Authenticated administrator download routes serve the original bytes; the directory is not a public static mount. Existing SQLite source text is migrated to disk on library access.

## Source files and full Cisco catalog

**Administration → Discovery → SNMP polling → MIB library** has **Modules** and **Source files** tabs.
Modules are the preferred definitions for each module name; Source files includes alternate SMIv1/SMIv2
versions, bundled dependencies and sources that need attention. Search and paging are server-side.
Download preserves original source bytes. Files with parser errors or absent upstream dependencies are
retained and marked `error`; they cannot be enabled until corrected/reimported. Other files continue
importing independently. Existing usable built-in profiles remain available if a vendor replacement fails.

For a full repository import on the API host:

```bash
git clone --depth 1 https://github.com/cisco/cisco-mibs.git /var/lib/winfire/mib-sources/cisco-mibs
# Run as the service account, with the same DATA_DIR and SNMP_MIB_LIBRARY_DIR as the API.
DATA_DIR=/var/lib/winfire node scripts/import-cisco-mibs.mjs /var/lib/winfire/mib-sources/cisco-mibs
```

The importer records the repository commit and source URL, retains all discovered ASN.1 MIB source
files, and prefers `v2/` definitions over product-specific, `v1/` and archived duplicates. Compiler
results and missing-dependency errors are visible in the library and in `cisco-import-report.json`
beside the checkout. The full checkout also retains Cisco support lists and ancillary OID/schema files.
Those ancillary files are not ASN.1 collection modules.

Existing collection switches and selected objects are preserved. New catalog modules are stored with
collection disabled except a bounded discovery set for CDP, CPU, memory, sensors, FRU, VLAN membership
and StackWise. Built-in standard/vendor collection profiles retain their selected table roots. Enable
additional modules and select relevant objects in Modules → Details / Configure; the existing device
matching and per-poll limits apply. Importing the catalog does not perform a device poll.

Back up **both SQLite and the library directory**. Keep an alternate `SNMP_MIB_LIBRARY_DIR` on a
persistent volume writable only by the service account. No hard-coded total storage limit applies;
monitor disk capacity. Retained source versions are intentionally not deleted when a collection profile
is removed. The importer writes a catalog-import audit record. Cisco source is downloaded into server
state, not checked into the application repository.

## LibreNMS catalog and vendor folders

The [LibreNMS MIB collection](https://github.com/librenms/librenms/tree/master/mibs) groups
vendor definitions in named subfolders. Download just that part of the repository using a sparse
checkout, then run the importer as the API service account with its storage environment:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/librenms/librenms.git /var/lib/winfire/mib-sources/librenms
git -C /var/lib/winfire/mib-sources/librenms sparse-checkout set mibs
DATA_DIR=/var/lib/winfire node scripts/import-librenms-mibs.mjs /var/lib/winfire/mib-sources/librenms
```

The importer recursively retains every regular file under `mibs/`, including extensionless MIBs.
It preserves original bytes, repository revision, source URLs and folder names such as
`mibs/cisco/CISCO-CDP-MIB`. Symbolic links are not followed. In **Source files**, search a vendor
folder (for example `mibs/juniper/`) or module name to find and download its sources.

Working definitions already in the library, including Cisco imports and curated profiles, are
preserved with their matching rules, switches, selections and device links. Sources with the same
module name remain downloadable as alternate versions. Identical sources are stored once on disk
but retain their separate repository entries. A newly compiled module starts with collection disabled;
configure its device match and readable objects before enabling it. Catalog imports do not poll hosts.

For new module names, root/common definitions are preferred, then the shortest path and lexical
filename order. If a candidate cannot compile, other definitions of the same module are tried.
Dependencies favor the nearest vendor folder, then common definitions, then the existing library
when the repository lacks a dependency. The chosen source dependencies are recorded in module
metadata. Parsing is bounded per module; invalid definitions and missing dependencies are marked
**Needs attention** while all source files remain downloadable. This does not guarantee that every
definition can compile or that every device implements it.

Rerunning the command adds missing definitions and retries failed modules without replacing working
ones. To deliberately replace a working module, download the desired source and dependencies,
then use **Import MIBs → Replace existing modules** and review the preview. The importer writes
`librenms-import-report.json` beside the checkout, with counts and per-file errors, plus an audit record.
Back up both the database and the source library before a large import.

## Matching and subsequent polls

A successful `sysDescr` or `sysObjectID` response establishes the device identity before optional collection. The poller evaluates enabled profiles:

- Standard built-in profiles probe common capabilities on every SNMP device.
- Vendor matches use a **numeric sysObjectID prefix** (exact match or descendant) or a **case-insensitive literal sysDescr phrase**. Conditions are ORed. A Cisco `.9` prefix cannot accidentally match `.99` or an unrelated `.9` component elsewhere in an OID.
- Matching sources, match evidence, module IDs and collection results are linked in `node_snmp_mibs`. The facts snapshot records imported source hashes. Existing links are recognized on the next poll when the device identity is unchanged.
- Identity is rechecked each time. New matching imports join the plan; disabled/removed sources stop being queried. A changed identity is matched again. A matching MIB is a candidate capability, not proof that every object is implemented.
- Standard profiles are collected first, then previously linked sources before new vendor matches. Narrow object selections if the collection budget is reached.

The UI distinguishes `supported`, `partial`, `unsupported`, `error`, `timeout`, and `skipped`. Missing optional ARP/bridge/MIB tables no longer fail SNMP identity verification. Authentication failures still fail the poll. Existing ESXi nodes retain API management while SNMP enriches their facts.

ARP entries from both legacy and modern IP-MIB tables, and VLAN-aware forwarding entries, feed existing discovery/mapping paths. External peers remain observable; candidate registration continues through the configured local inventory boundary. IPv6 neighbor/address/route observations are retained as MIB values; the current ARP candidate registrar remains IPv4-only. LLDP is retained as evidence; it does not itself create inventory assets or prove physical attachment.

## Included collection profiles

| MIB/profile | Additional information |
|---|---|
| IF-MIB | Interface inventory, status, speeds, MACs, names and extended counters. |
| ENTITY-MIB | Physical components, serial/model/manufacturer and hardware/firmware/software revisions. |
| HOST-RESOURCES-MIB | Memory size, storage, devices and per-processor load. |
| IP-MIB | Modern IPv4/IPv6 neighbors and assigned addresses. |
| IP-FORWARD-MIB | Modern IPv4/IPv6 routes. |
| TCP-MIB | Modern TCP connections and listeners. |
| Q-BRIDGE-MIB | VLAN-aware forwarding database and current VLAN membership. |
| LLDP-MIB | Remote system names, capabilities and port relationships. |
| CISCO-ENVMON-MIB | Voltage, temperature, fan and supply state. |
| BEGEMOT-PF-MIB | PF counters, interface/table/queue statistics when the device enables its PF module. |
| MIKROTIK-MIB | RouterOS system and hardware-health subtrees. |
| VMWARE-SYSTEM-MIB | Product name, version and build; supplements ESXi API collection. |
| SNWL-COMMON-MIB | SonicWall model, serial, firmware, ROM and asset identity. |
| NS-ROOT-MIB | NetScaler system subtree. |

Legacy system identity, ARP, bridge forwarding, routes and TCP tables continue to be collected. PF MIB values are counters/statistics, not a guaranteed export of all firewall connection tuples. MIB support varies by model, firmware, SNMP view and enabled modules. Imported definitions cannot make an agent expose unsupported data.

## Updating, disabling and removing

An identical reimport is a no-op. A changed module or replacement of a curated built-in profile requires the **Replace existing modules** switch. Imported replacements keep matching criteria, enabled state and surviving selected object names; replacing a curated profile selects the first 64 imported readable objects. Dependent imported modules are recompiled in the same transaction. Replacing a dependency with incompatible symbols fails validation rather than leaving a partially broken library.

Disable modules or individual objects with switches to stop future queries. Built-in profiles can be disabled; imported modules can be removed if no other imported module depends on them. Removing an imported source removes its active device links but retains the last node snapshot. Removing an imported replacement of a curated profile restores the built-in profile when the library is next accessed; disable it if no collection is wanted. Node details distinguish disabled/removed sources from the last recorded collection.

## Limits and persistence

- Import: 20 files, each at most 8 MiB, combined at most 32 MiB per request using multipart `files` fields. JSON request bodies retain the application's 2 MB HTTP body limit. Temporary Multer files are removed after preview/import and rejected uploads.
- Library storage has no module-count or aggregate-byte quota: capacity is the available server filesystem. Per-request validation loads only affected modules and dependencies, with a 32 MiB compilation budget, a 10-second worker timeout and bounded memory. Only one API validation runs at a time. Large catalog imports run through the server CLI, one module/dependency graph at a time; their workers have a 15-second deadline and 256 MiB memory limit.
- Collection: 64 selected objects/module, four concurrent library queries, 128 queries and 8,192 values per device library pass, at most 1,024 values per object walk. The pass has a 30-second budget; each optional query has a maximum 5-second duration. These limits are independent of the initial identity and four legacy table queries.
- Legacy tables: each walk is capped at 2,048 values / 6 seconds. Limits are retained as collection diagnostics. Large tables can be incomplete.
- String values are capped at 1,024 characters; binary values are shown as bounded hexadecimal. Counter64 values retain exact decimal precision. The UI browses retained values using server-side paging/search.
- The most recent device collection lives in `node_facts`. Links live in `node_snmp_mibs`; library configuration lives in `snmp_mib_library`; `snmp_mib_files` indexes the filesystem sources and alternate versions. Existing target poll history retains its normal behavior; this is not a time-series store.
- Library import/configuration/deletion requires Administration permission and is audited. Node collection reads use the existing authenticated node-facts access model. SNMP credentials remain encrypted in the credential vault, separate from MIB source files.

## API and curl examples

All paths are relative to `/api/v1`. Set `BASE` to the server origin and `TOKEN` to an operator access token. Library changes require an owner/admin permission grant. Use the vault and existing SNMP target/node polling APIs to authenticate to a device; these endpoints never accept device secrets.

```bash
# List built-in and imported sources, defaulting to 25 rows.
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/discovery/snmp-library?source=all&search=CISCO&sort=name&direction=asc&page=1&limit=25"

# Multer multipart import (repeat files for dependencies).
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  -F 'replace=true' -F 'files=@CISCO-SMI.my' -F 'files=@CISCO-ENVMON-MIB.my' \
  "$BASE/api/v1/discovery/snmp-library/preview"
# Use the same multipart fields with /import after reviewing the preview.

# Download an original source; IDs come from the paginated /files endpoint.
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/discovery/snmp-library/files/$FILE_ID/download" -o module.my

# Encode exact source text (including newlines) with jq, never shell interpolation.
jq -n --rawfile smi CISCO-SMI.my --rawfile mib CISCO-ENVMON-MIB.my \
  '{replace:true,files:[{filename:"CISCO-SMI.my",content:$smi},{filename:"CISCO-ENVMON-MIB.my",content:$mib}]}' \
  > /tmp/winfire-mib-import.json

curl --fail-with-body -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @/tmp/winfire-mib-import.json "$BASE/api/v1/discovery/snmp-library/preview"

# After reviewing the preview:
curl --fail-with-body -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @/tmp/winfire-mib-import.json "$BASE/api/v1/discovery/snmp-library/import"

# Inspect resolved objects, selected names, dependencies and up to 100 device links.
curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/discovery/snmp-library/$MIB_ID?search=Temperature&page=1&limit=25"

# Set matching and collection using object names returned by the detail endpoint.
curl --fail-with-body -X PATCH -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled":true,"match":{"sysObjectIdPrefixes":["1.3.6.1.4.1.9"],"sysDescrContains":["Cisco"]},"selectedObjects":["ciscoEnvMonTemperatureStatusValue"]}' \
  "$BASE/api/v1/discovery/snmp-library/$MIB_ID"

curl --fail-with-body -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/nodes/$NODE_ID/snmp-mibs?search=Serial&page=1&limit=25"

curl --fail-with-body -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/v1/discovery/snmp-library/$MIB_ID"
```

Validation failures return 400; conflicting replacements/dependencies or concurrent library changes return 409; missing records return 404. Source lists never include raw imported content. The [generated route reference](API_ROUTES.md) and live OpenAPI document query parameters and request schemas.

## Research and vendor downloads

- IETF defines [IF-MIB](https://www.rfc-editor.org/info/rfc2863/), [ENTITY-MIB](https://www.rfc-editor.org/info/rfc4133/), [HOST-RESOURCES-MIB](https://www.rfc-editor.org/info/rfc2790/), [IP-MIB](https://www.rfc-editor.org/info/rfc4293/), [IP-FORWARD-MIB](https://www.rfc-editor.org/info/rfc4292/), [TCP-MIB](https://www.rfc-editor.org/info/rfc4022/) and [Q-BRIDGE-MIB](https://www.rfc-editor.org/info/rfc4363/). IEEE maintains the [LLDP standard](https://www.ieee802.org/1/pages/802.1ab.html).
- Cisco publishes [CISCO-ENVMON-MIB and dependencies](https://github.com/cisco/cisco-mibs/tree/main/v2). The importer was exercised with the actual CISCO-ENVMON-MIB and CISCO-SMI sources.
- Netgate documents the [MIB-II, PF, host-resource and UCD modules](https://docs.netgate.com/pfsense/en/latest/services/snmp.html); FreeBSD publishes [BEGEMOT-PF-MIB](https://github.com/freebsd/freebsd-src/blob/main/usr.sbin/bsnmpd/modules/snmp_pf/BEGEMOT-PF-MIB.txt).
- MikroTik documents [SNMP capabilities and slow-service limits](https://help.mikrotik.com/docs/spaces/ROS/pages/8978519/SNMP). Obtain the MIB matching your RouterOS release from MikroTik's download page.
- Broadcom documents [VMware MIB downloads](https://knowledge.broadcom.com/external/article?legacyId=1013445) and [VMWARE-SYSTEM-MIB queries](https://knowledge.broadcom.com/external/article?legacyId=2145018). SNMP does not replace ESXi SOAP inventory.
- SonicWall explains [obtaining vendor OIDs/MIBs from MySonicWall](https://www.sonicwall.com/support/knowledge-base/sonicwall-oid-values-from-the-mib-files/kA1VN0000000HVZ0A2) and [SNWL-COMMON-MIB identity fields](https://help.sonicwall.com/help/sw/eng/6360/7/0/0/content/Chapter3_System/System_Diagnostics.htm).
- NetScaler documents [downloading MIBs from the appliance](https://docs.netscaler.com/en-us/citrix-adc/current-release/system/snmp.html) and its [enterprise OID reference](https://developer-docs.netscaler.com/en-us/adc-snmp-oid-reference/current-release.html).

Use vendor-provided MIBs appropriate to the appliance/firmware and include their dependency files. Proprietary vendor source MIBs are not redistributed with WinFire.
