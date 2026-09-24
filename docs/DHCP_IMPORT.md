# Windows DHCP lease import

DHCP imports are optional, passive inventory enrichment. They are useful when SNMP/ARP collection misses a device between scans. WinFire reads a JSON export; it does not log into the DHCP server, scan clients, bind credentials, start training, or infer an OS from a lease. Subsequent explicit scans, credential assignment, and normal management polling remain independent.

## Export current leases

On Windows with the **DhcpServer** PowerShell module (DHCP management tools/RSAT) and an account permitted to read the server's scopes and leases, run the script from this repository:

```powershell
.\scripts\Export-DhcpLeases.ps1 -ComputerName dhcp.example.com -OutputDirectory C:\Exports\WinFire

# Restrict the export to particular scopes:
.\scripts\Export-DhcpLeases.ps1 -ComputerName dhcp.example.com `
  -ScopeId 192.168.50.0,192.168.60.0 -OutputDirectory C:\Exports\WinFire
```

The script enumerates scopes when none are specified, requests current active IPv4 leases, projects simple string fields, converts times to UTC, and splits output into batches of at most 2,000 leases. One lease still produces an array. Empty exports produce no file. Output names are `winfire-dhcp-001.json`, etc.; use a fresh output directory for each export to avoid retaining files from an older, larger export.

Microsoft documents scope enumeration and active-lease behavior in [Get-DhcpServerv4Lease](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/get-dhcpserverv4lease?view=windowsserver2025-ps). Explicit projection avoids depending on nested CIM/IPAddress serialization; JSON export uses [ConvertTo-Json](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json).

This feature does not import a DHCP server backup, CSV, DHCPv6 DUIDs, or arbitrary client identifiers. Only Ethernet MACs and Ethernet client IDs with an optional `01` hardware-type prefix are accepted. The PowerShell script must be run in your Windows environment; WinFire does not require the DHCP module on its API host.

## Import in the interface

1. In **Administration → Server config**, configure **Local asset CIDRs**. These are the inventory boundary; include every LAN/WAN subnet you own and monitor.
2. Open **Administration → Discovery → DHCP leases**.
3. Choose the JSON export or paste its contents. The UI accepts files up to 1.5 MB; the API has a 2 MB request limit and a 2,000-lease limit.
4. Select **Preview import**. The server validates the export and calculates results against current inventory. Preview changes nothing.
5. Review the row reasons. Select **Import eligible leases**. Import checks the current inventory again in a database transaction, so a preview may differ if another discovery completed in between.
6. Review **Import history → View report** and the asset's **DHCP lease evidence** in node details. History uses server pagination, 25 imports per page.

Administrators (or custom roles with `portal.admin`) can preview, import, and read history. Retained node evidence is part of the normal node details response. DHCP reports contain device names and addresses; they contain no DHCP or management passwords.

## Matching and state rules

| Result | Behavior |
|---|---|
| New | Create one local asset with `inventory_source=discovery`, `discovery_source=dhcp:<import-id>`, `status=unknown`, `firewall_state=unmanaged`, and `agent_required=1`. No reachability, verification, OS, or management capability is asserted. |
| Enriched by MAC | Attach source, observation time, hostname, IP, MAC and expiry. A changed address updates only an unmanaged discovery asset with no prior successful management. Managed addresses are preserved, with the lease address available as evidence. |
| Enriched by IP | Use only an unambiguous IP match with no conflicting MAC or hostname. Fill an absent MAC and replace only a placeholder hostname. Authenticated names, OS facts, credentials, transport and firewall state stay intact. |
| Skipped | Outside local CIDRs, expired lease, non-active state, malformed row identity, or an equal/newer observation already exists. |
| Conflict | Duplicate IP/MAC in the batch, multiple inventory matches, MAC and IP identify different assets, or IP has a different MAC/name. Review the inventory; automatic merging is not attempted. |

MAC matching ignores case and separators. Accepted states are `Active` and `ActiveReservation` (case insensitive). Expiry must be later than both import time and observation time. Observation timestamps more than five minutes in the future are rejected. ISO 8601 timestamps must include a timezone. Non-date or missing required fields reject the entire request; validly shaped rows with ineligible content appear in the report.

Repeated submission of the identical payload returns the original report with `replayed: true`; it creates no extra assets or import records. A new observation can enrich the same asset. Lease expiry does not delete inventory or mark a host unreachable. Deletion from DHCP is not proof a device has disappeared.

External addresses are never promoted to assets by this import. Existing event/mapping observations are untouched. Import reports retain skipped addresses for review, which does not make them inventory assets.

## JSON contract and API

```json
{
  "source": "dhcp.example.com",
  "observedAt": "2026-09-24T12:00:00Z",
  "leases": [
    {
      "ip": "192.168.50.25",
      "mac": "00-11-22-33-44-55",
      "hostname": "printer.example.com",
      "leaseExpiry": "2026-09-25T12:00:00Z",
      "state": "Active"
    }
  ]
}
```

Use current times in actual requests. `source`, `observedAt`, and `leases` are required. Each lease requires `ip`, `mac`, and `leaseExpiry`; `hostname` defaults to empty and `state` to `Active`. Unknown fields are rejected. See [authentication examples](API.md#authentication).

```bash
curl --fail-with-body "$BASE/discovery/dhcp/preview" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @winfire-dhcp-001.json

curl --fail-with-body "$BASE/discovery/dhcp/import" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @winfire-dhcp-001.json

curl --fail-with-body "$BASE/discovery/dhcp/imports?page=1&pageSize=25" \
  -H "Authorization: Bearer $TOKEN"
curl --fail-with-body "$BASE/discovery/dhcp/imports/$IMPORT_ID" \
  -H "Authorization: Bearer $TOKEN"
```

Preview returns `source`, `observedAt`, `summary` (`created`, `enriched`, `skipped`, `conflict`, `total`), and `rows`. Import returns those fields plus `id`, `importedAt`, and `replayed` with HTTP 201. Each row has its normalized identity, proposed/applied `action`, `reason`, and `nodeId` when correlated. History returns `items`, `page`, `pageSize`, `total`, `totalPages`; reports return every row in that batch.

## Troubleshooting

- **409 Configure Local asset CIDRs:** save your inventory boundary first. Unlike the legacy unscoped inventory view, DHCP import requires an explicit boundary.
- **All rows expired:** generate a fresh export and check clocks/timezone conversion on the exporter and server.
- **Invalid MAC/client ID:** some DHCP clients use non-Ethernet IDs. Do not invent a MAC; collect identity through another discovery source.
- **Conflict:** inspect both the lease and existing node's MAC, management address and hostname. Correct the source or inventory explicitly, then export again.
- **Unknown / Unmanaged after import:** expected. A lease allocation does not establish live connectivity or authenticate a management credential.
- **Need automation:** schedule the exporter and authenticated API submission externally. Built-in recurring CIDR scans do not schedule DHCP imports. Rotate API sessions using the normal refresh-token flow.
