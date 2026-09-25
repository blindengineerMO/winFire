# User API keys and MCP reporting keys

Open **Administration → Security → API keys** (direct link:
`/admin?tab=security&securityTab=api-keys`). This view lists keys with their owner, purpose,
nonsecret prefix, state, expiry and last successful authentication time. Search, filters,
sorting and pagination are performed by the API; the default page size is 25.

## Create and administer keys

1. Choose **Create API key**, give it a descriptive name and select an expiry (90 days by
   default, at most one year). Administrators may choose another permitted user as owner.
2. Select **WinFire API** or **MCP AI usage reporting**. For API automation, leave
   **Allow API writes** off for read-only access. Writes still require the owner's role
   permissions; this switch does not grant an auditor administrator rights.
3. For MCP keys, administrators may select a reporting node using the node search. A personal
   key created without a node records user-attributed, unmapped AI usage. Unbound keys cannot
   claim another node ID. Node binding and purpose are fixed; create a replacement to change them.
4. Copy the secret from the one-time dialog and store it in the calling client's secret store.
   Closing the dialog clears the displayed secret. It cannot be retrieved later.
5. Use **Edit** for the name or expiry, **Rotate** for a replacement secret, **Revoke** to
   disable authentication while retaining the row, or **Delete** to invalidate and remove it.
   Rotation invalidates the old secret immediately. Updating expiry does not reactivate a
   revoked key. Deleting/revoking an MCP key revokes its dedicated reporter while retaining
   historical usage and audit records.

Users manage their own keys. Administrators can administer users with equal or lower
permissions; an administrator cannot mint an owner's key. Suspended users' keys stop working
immediately and remain available to administrators for revocation. User deletion removes keys;
disabled/missing AD identities cannot authenticate them. Ordinary session logout or password
rotation does not itself revoke automation keys: use key revocation for that purpose.

Only a SHA-256 hash of each random 256-bit key is stored. Tokens begin with `wfuk_`. API
responses/audits list metadata only; creation and rotation are the sole responses containing
the secret, and key-management responses use `Cache-Control: no-store`. Successful-use timestamps
are updated at most once per minute. Key administration requires a signed-in user session:
an automation key cannot list, create, rotate or delete other keys.

## Scopes and endpoints

| Key purpose | Granted scopes | Permitted use |
| --- | --- | --- |
| API, read only | `api:read` | Authenticated GET/HEAD requests under `/api/v1`, subject to the owner's current permissions |
| API, writes enabled | `api:read`, `api:write` | API reads and mutations subject to the same current permissions |
| MCP AI usage reporting | `mcp:report` | `report_ai_usage` and `report_ai_usage_batch` at `/mcp/ai-usage`, bound to the key's dedicated reporter and owner |

An API key is not an enrolled-agent certificate, browser-device token, WEF credential, or
REST/stdio `wfai_` reporter credential. MCP keys cannot access inventory or operator routes.
The MCP server currently exposes AI reporting tools, not general inventory administration tools.

All keys are sent in the HTTP `Authorization: Bearer <key>` header, never in query strings or
tool arguments. Use HTTPS for remote access.

```bash
# Read the key without echoing it or embedding it in shell history.
read -rs WINFIRE_KEY
curl -sS "$WINFIRE_URL/api/v1/nodes?page=1&pageSize=25" \
  -H "Authorization: Bearer $WINFIRE_KEY"
unset WINFIRE_KEY
```

## MCP clients

Configure a Streamable HTTP MCP connection with the URL shown in the one-time key dialog
and an Authorization header supplied by your client's secret store:

```json
{
  "url": "https://winfire.example.com/mcp/ai-usage",
  "headers": {"Authorization": "Bearer <MCP key from your secret store>"}
}
```

The exact configuration wrapper depends on the client; the URL/header above are the transport
settings. Reporting is metadata only. Use stable event IDs for retries; the existing receipt
and node-binding checks apply to key-authenticated reports.

MCP keys do **not** require `AI_OAUTH_ISSUER`. Configure **Server config → Public base URL**,
`PUBLIC_BASE_URL`, or the explicit `AI_MCP_RESOURCE_URL` so the MCP endpoint has the correct
external host. Explicit `AI_MCP_RESOURCE_URL` takes precedence. Production requires an explicit
public URL and HTTPS. Local nonproduction development defaults to
`http://localhost:<PORT>/mcp/ai-usage` and allows loopback HTTP. Host and Origin validation remain
active; additional browser origins use `AI_MCP_ALLOWED_ORIGINS`. With TLS termination, configure
the application's trusted proxy setting so requests are recognized as HTTPS.

OAuth clients remain supported using the existing configured provider and `ai:report` scope.
OAuth discovery requires that provider; clients using a manually configured MCP key/header
connect directly without OAuth discovery. A missing OAuth provider does not disable key access.

## Key-management API

Use a **user-session JWT**, obtained through normal user authentication, for these endpoints.
Generated API keys deliberately cannot call them. All paths use `/api/v1`.

| Method and route | Operation |
| --- | --- |
| `GET /api-keys/options` | Permitted owner choices and configured MCP URL |
| `GET /api-keys` | Search/filter/sort/page metadata; `owner=self` by default, `owner=all` for administrators |
| `POST /api-keys` | Create a key; returns `{key, secret}` once |
| `PATCH /api-keys/:id` | Update name and/or future expiry |
| `POST /api-keys/:id/rotate` | Immediately replace the secret; returns `{key, secret}` once |
| `POST /api-keys/:id/revoke` | Revoke key authentication |
| `DELETE /api-keys/:id` | Delete the entry and invalidate authentication |

```bash
curl -sS "$WINFIRE_URL/api/v1/api-keys?owner=self&status=active&page=1&pageSize=25" \
  -H "Authorization: Bearer $WINFIRE_SESSION_TOKEN"

# key-request.json contains the example below with a valid future expiry.
# This response contains a secret: consume it directly into your client's secret store.
curl -sS "$WINFIRE_URL/api/v1/api-keys" \
  -H "Authorization: Bearer $WINFIRE_SESSION_TOKEN" \
  -H 'Content-Type: application/json' --data-binary @key-request.json

curl -sS -X POST "$WINFIRE_URL/api/v1/api-keys/$KEY_ID/revoke" \
  -H "Authorization: Bearer $WINFIRE_SESSION_TOKEN"
```

Example create payload (replace expiry with a future UTC timestamp within one year):

```json
{
  "name": "Inventory integration",
  "purpose": "api",
  "access": "read",
  "expiresAt": "2026-12-24T00:00:00Z"
}
```

For MCP use `purpose: "mcp"` and omit `access` or set it to `read`; this selects reporting
access, not API reads. Administrators can include `userId` and `nodeIds` (up to 100).
List parameters: `q`, `owner`, `status` (`all/active/expired/revoked`), `purpose`
(`all/api/mcp`), `sort` (`name/created/expires/used`), `direction`, `page`, `pageSize`.
See `/api/v1/openapi.json` for request schemas.

Migration 109 adds the key table to the existing database. Back up using the application's
normal SQLite/vault/PKI backup procedure before updating. Restart the API after deploying the
frontend and server together so the Security view can reach its key-management routes.

### API key page unavailable

If Security → API keys reports that API key management is unavailable, check the API
served at the same origin as your browser. Its `/api/v1/openapi.json` should include
`/api-keys/options` and `/api-keys/`. A frontend update alone does not load new routes
into an already running Node process: deploy both parts and restart the API service.
Select **Refresh** afterward to retry both the key list and creation options. A failed
options request keeps Create disabled until those options load successfully.
