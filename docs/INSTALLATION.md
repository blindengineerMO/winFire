# Installation and configuration

## Runtime and host requirements

Use **Node.js 24 LTS** for parity with the Docker image. The package declares Node >=20, but the installed Vite 7 toolchain needs a recent supported Node release; Node 24 is the documented baseline. Install npm, Git, Python 3 with venv support, OpenSSL, and C/C++ build tools if native npm prebuilds are unavailable. Linux discovery also uses OS networking utilities (`ping`, `arping` where available); SSH itself uses the Node `ssh2` client. Windows agentless management uses the Python sidecars in `api/sidecar` and dependencies in their requirements file.

The API stores data in **SQLite**, including migrations applied automatically at startup. Give the service account a persistent writable `DATA_DIR`, protect it from other users, and keep a single API instance writing that database. `POSTGRES_URL`/`DATABASE_URL` in the Dokploy stack do not switch the current database adapter to PostgreSQL.

Allow the control plane to reach the protocols you use: WinRM HTTPS 5986 (HTTP 5985 where enabled on the remote host), SSH 22, SNMP UDP 161, ESXi HTTPS 443, and directory LDAPS 636. WMI/DCOM and SMB fallback require their host-specific RPC/SMB connectivity and permissions. Clients need the public HTTPS origin for the portal and agents; optional SMTP/Entra/webhooks need outbound connectivity.

## Native installation

From a checkout:

```bash
npm ci
npm run setup:winrm
cp .env.example .env
chmod 600 .env
```

Edit `.env` before starting. Replace the placeholder vault/JWT secrets; generate values independently:

```bash
openssl rand -base64 32   # VAULT_MASTER_KEY: exactly 32 decoded bytes
openssl rand -hex 32     # JWT_SECRET
```

A minimal production environment is:

```dotenv
NODE_ENV=production
HOST=127.0.0.1
PORT=3000
DATA_DIR=/var/lib/winfire
JWT_SECRET=replace-with-generated-secret
VAULT_MASTER_KEY=replace-with-generated-base64-key
BOOTSTRAP_EMAIL=owner@example.com
BOOTSTRAP_PASSWORD=replace-with-a-unique-long-password
BOOTSTRAP_ADMIN_ENABLED=false
PUBLIC_BASE_URL=https://winfire.example.com
CORS_ORIGIN=https://winfire.example.com
```

Create the data directory for the account running WinFire. The application **does not automatically load `.env`**. Use a process manager that injects it, or Node's explicit environment-file option:

```bash
npm run build
node --env-file=.env api/src/server.js
```

If the environment is already exported, `npm start` builds and starts the app. Without TLS material this listener is HTTP; terminate HTTPS at a trusted reverse proxy for browser use, or configure native TLS below. `HOST=0.0.0.0` is needed for container/public interface binding; loopback binding is appropriate for a local reverse proxy.

Verify the deployment:

```bash
curl --fail http://127.0.0.1:3000/api/v1/health
curl --fail http://127.0.0.1:3000/api/v1/openapi.json -o openapi.json
```

`/health` confirms the process is responding; it does not validate every remote host, directory or credential. Sign in, configure local CIDRs, add one credential, and preflight a representative host before a broad discovery scan.

### Bootstrap accounts: owner versus demo administrator

`BOOTSTRAP_EMAIL` and `BOOTSTRAP_PASSWORD` create the first **owner** only when the users table is empty. If omitted, a default owner email and generated password are logged on first startup. The first-login log includes the initial password; protect and rotate that credential after provisioning. Later starts do not reset this owner.

The separate `BOOTSTRAP_ADMIN_*` settings control a **demo admin**. It is enabled by default outside production and disabled by default in production. When enabled, each restart reconciles its configured email/password, admin role, suspension, lockout, and TOTP state. Changing its password only in the UI will not survive that reconciliation. Set `BOOTSTRAP_ADMIN_ENABLED=false` in production; an existing marked demo account is suspended and its sessions revoked. Do not confuse disabling this demo account with deleting the independently provisioned owner.

### Service supervision

Example systemd unit (adjust account and checkout path):

```ini
[Unit]
Description=WinFire control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=winfire
Group=winfire
WorkingDirectory=/opt/winfire
EnvironmentFile=/etc/winfire/winfire.env
ExecStart=/usr/bin/node /opt/winfire/api/src/server.js
Restart=on-failure
RestartSec=5
UMask=0077
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
```

Build the UI before starting this unit. Enable/start it with your normal systemd deployment process. Use `journalctl -u winfire` for startup and scheduled-job errors. WinRM interpreter discovery finds `.venv/bin/python` in the checkout; set `WINRM_PYTHON` explicitly if the virtual environment lives elsewhere.

## Docker

```bash
docker build -t winfire:local .
docker volume create winfire-data
docker run -d --name winfire --restart unless-stopped \
  --env-file .env -e HOST=0.0.0.0 -e DATA_DIR=/data \
  -p 127.0.0.1:3000:3000 -v winfire-data:/data winfire:local
```

The Docker build includes the frontend build, API tests, native dependencies, and Python environment. Mount TLS files read-only if configured and ensure environment paths refer to container paths. The `/data` volume holds the active database, uploads and deployment-managed material. Do not remove it during upgrades. The root Docker image does not include all optional host networking tools; install/provision ICMP/ARP utilities and required capabilities for your deployment if using those discovery methods. TCP fallbacks remain separate.

## Dokploy

Run `npm run deploy:dokploy` from a trusted machine that reaches Dokploy. The wizard requests the Dokploy URL/API key, project/environment, repository/branch, service name, DNS domain, and bootstrap values. It creates a random subdomain and separate API/UI/PostgreSQL services from `deploy/dokploy/docker-compose.yml`, configures routing and checks deployment reachability. The API key is process-only.

Environment overrides include `DOKPLOY_URL`, `DOKPLOY_API_KEY`, `DOKPLOY_PROJECT_ID`, `DOKPLOY_ENVIRONMENT_ID`, `WINFIRE_SERVICE_NAME`, `WINFIRE_BASE_DOMAIN`, `WINFIRE_BOOTSTRAP_EMAIL`, `WINFIRE_BOOTSTRAP_PASSWORD`, `WINFIRE_GITHUB_REPOSITORY`, `WINFIRE_GITHUB_BRANCH`, and `WINFIRE_HTTPS`. `DOKPLOY_REACHABILITY_IP` tests routing before DNS propagation while retaining Host/SNI. Point the hostname at Dokploy. Let's Encrypt requires a public name and reachable validation ports; `WINFIRE_HTTPS=false` is for internal HTTP test deployments.

The UI container proxies `/api` to the API; the active database is still the persistent **API SQLite volume**. PostgreSQL is provisioned for future adapter work. Do not back up only PostgreSQL and expect to recover inventory. Review the wizard's bootstrap settings and disable the demo admin after provisioning a permanent owner.

## TLS, proxying and agent certificates

Native HTTPS requires all four PEM files together: `TLS_CERT`, `TLS_KEY`, `AGENT_CA_CERT`, `AGENT_CA_KEY`. They can be uploaded in **Administration → TLS** or provided by environment paths; environment paths win. Uploaded files are under `DATA_DIR/tls` and require restart. Partial native TLS configuration prevents startup.

In production, both private keys must be encrypted PKCS#8 PEM (`BEGIN ENCRYPTED PRIVATE KEY`) with `TLS_KEY_PASSPHRASE` and `AGENT_CA_PASSPHRASE`. Use a server certificate trusted by clients and an agent CA whose signing key is protected. Agent enrollment signs short-lived client certificates; subsequent agent endpoints validate the actual TLS socket's trusted peer certificate and enrolled fingerprint.

A reverse proxy terminating ordinary HTTPS is sufficient for the browser portal, but **forwarded certificate headers do not replace native agent mTLS**. Use TCP TLS passthrough or a separate directly reachable native TLS endpoint for enrolled agent operations. The checked-in Dokploy HTTP UI proxy alone does not provide this channel.

Set `PUBLIC_BASE_URL` to the exact HTTPS origin that users reach; it overrides Server config. Set `TRUST_PROXY_CIDRS` only to actual trusted proxies. It controls how Express derives the browser source IP, which is used in JIT grants. Verify the reported IP before enabling portal grants behind NAT or a proxy.

## Configuration reference

Secrets are environment/deployment settings; most operator settings are persisted through Administration. Restart to apply environment changes.

| Setting | Purpose / default |
|---|---|
| `NODE_ENV` | `production` requires explicit vault/JWT secrets and encrypted native TLS keys. |
| `HOST`, `PORT` | Listener; defaults `0.0.0.0`, `3000`. |
| `SNMP_MIB_LIBRARY_DIR` | MIB source storage directory; default `DATA_DIR/snmp-mibs`. No total library quota; back up with SQLite and persist on a writable volume. |
| `DATA_DIR` | Persistent state; default `./data` relative to working directory. |
| `JWT_SECRET` | Access-token signing secret, at least 32 characters in production. |
| `VAULT_MASTER_KEY` | Base64 encoding of exactly 32 bytes; retain for decrypting stored credentials and MFA secrets. |
| `BOOTSTRAP_EMAIL`, `BOOTSTRAP_PASSWORD` | Initial owner on an empty users table. |
| `BOOTSTRAP_ADMIN_ENABLED/EMAIL/PASSWORD` | Separate restart-reconciled demo account; disable in production. |
| `PUBLIC_BASE_URL`, `SERVER_FQDN` | Override saved external URL and host identity. |
| `CORS_ORIGIN` | Comma-separated allowed browser origins for cross-origin API access. |
| `TRUST_PROXY_CIDRS` | Trusted proxy addresses/CIDRs; do not trust arbitrary forwarded headers. |
| `TLS_CERT`, `TLS_KEY`, `TLS_KEY_PASSPHRASE` | Native server TLS material. |
| `AGENT_CA_CERT`, `AGENT_CA_KEY`, `AGENT_CA_PASSPHRASE` | Agent client certificate issuer. |
| `WINRM_PYTHON`, `WMI_PROBE_PYTHON`, `NETSH_PYTHON` | Interpreter overrides for management sidecars. |
| `WINRM_TLS_VERIFY` | Sidecar HTTPS certificate validation; validates by default. `false` disables that check. |
| `WINFIRE_CONTROL_PLANE_IPS` | Comma-separated addresses protected from management-cutoff rules. |
| `SWEEP_INTERVAL_MINUTES` | Verification/drift sweep; example default 60. |
| `LOG_POLL_INTERVAL_SECONDS`, `LOG_POLL_CONCURRENCY` | Fleet event collection; defaults 120 seconds / 4 workers. |
| `TRAINING_SWEEP_INTERVAL_MINUTES` | Due-training sweep; default 5 minutes. |
| `MFA_EVENT_POLL_SECONDS` | Prompt event polling; default 30, minimum 15 seconds. |
| `AUTH_RATE_LIMIT` | Login limiter; example value 20. |
| `CREDENTIAL_ROTATION_FAILURE_WINDOW_MINUTES`, `CREDENTIAL_ROTATION_FAILURE_THRESHOLD` | Correlated credential failure notice thresholds. See `/credentials/health` for effective values. |
| `WEF_SHARED_SECRET` | Overrides encrypted WEF receiver secret in Administration. Enable WEF through saved settings. |
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` | Optional Entra configuration; certificate credentials also support PEM values or `*_FILE` paths as shown in `.env.example`. |
| `SMTP_HOST/PORT/FROM/USER/PASSWORD` | Optional invitations and email verification delivery. Without SMTP, admins share generated links manually. |
| `NOTIFICATION_WEBHOOK_URL` | Optional HTTPS notification delivery endpoint. |
| `EXTENSION_ORIGINS` | Allowed Chrome/Edge/Firefox extension origins. |
| `INTERNET_POLICY_SIGNING_SECRET` | Separate browser-policy HMAC key; otherwise JWT secret is used. |
| `AGENT_PACKAGE_PATH`, `AGENT_MSI_PATH` | Signed downloadable agent packages. |
| `AGENT_UPDATE_PACKAGE_PATH`, `AGENT_PACKAGE_VERSION`, `AGENT_UPDATE_VERSION`, `AGENT_SIGNER_THUMBPRINT` | Agent self-update package/version and optional executable signer pin. |

`LOG_RETENTION_DAYS` appears in older example/deployment environments; the current maintenance code reads the persisted `log_retention_days` setting. Use **Administration → Logs and DNS / Observability** for effective retention, DNS refresh, compaction and loopback controls. `WEF_ENABLED` is likewise not an environment switch. `WINRM_INSECURE_HTTP` is a legacy example/Compose variable not read by the current connector; it does not disable HTTP probing or enforce HTTPS-only management. Restrict management connectivity at the host/network boundary when HTTPS-only access is required.

### First configuration checklist

1. Save Server config FQDN/public URL and explicit local asset CIDRs. Empty CIDRs leave the legacy inventory scope unrestricted; DHCP imports require nonempty CIDRs.
2. Add appropriately scoped vault credentials. Test Windows/SSH before binding; use a successful SNMP poll or ESXi facts collection for those transports.
3. Configure directory URL/search base/credentials and test. Keep LDAPS validation working; LDAP fallback is an explicit opt-in and does not retry bad credentials.
4. Choose discovery sources: CIDR, recurring scans, SNMP targets, Linux SSH defaults, passive ARP, DHCP lease files.
5. Configure training, event collection/audit policy, retention and notifications before scaling collection.
6. Verify one host's facts and management status, then expand discovery and review unmanaged assets.
7. Configure identity segments and verify fail-closed gates before JIT MFA. Follow [JIT MFA](JIT_MFA.md).

## Backup, upgrade and recovery

Back up the entire data directory and retain the original vault key, JWT key and TLS/agent CA material in your secret backup system. The database is in WAL mode: either stop the API and copy the directory, or use SQLite's online backup API; do not copy only `winfire.db` while it is changing. Take a pre-upgrade backup, install with `npm ci`, build, run tests, and restart. Migrations run automatically. Check health, login, inventory and collection errors after restart.

Restoring data without its vault key makes stored credentials unreadable. Changing the JWT secret invalidates access tokens. Disabling the demo admin does not recover an existing owner's password. Test recovery on a separate data directory and isolated network so restored schedulers cannot manage production hosts twice.

## Development and troubleshooting

```bash
npm ci
npm run setup:winrm
npm run dev:api      # environment must already be exported for this npm script
npm run dev:web     # second terminal; Vite proxies /api to localhost:3000
npm test
npm run build
npm run docs:api    # refresh generated route reference without using live state
```

For explicit `.env` loading in development: `node --env-file=.env --watch api/src/server.js`. Do not point tests or experimental builds at production `DATA_DIR`.

- **Vault-key error:** replace the example placeholder with valid 32-byte base64; preserve the existing key for an existing database.
- **UI stale:** rebuild and reload after frontend changes. Restart the API after route changes or migrations.
- **404 API:** check API prefix `/api/v1`, proxy routing and that the latest process was restarted.
- **WinRM authentication/transport failure:** verify sidecar dependencies, DNS/SPN, listener, account rights and TLS/HTTP policy; inspect the structured onboarding error in node details.
- **No firewall events:** verify host audit policy, event delivery and exclusions. An empty table alone does not mean no traffic occurred.
- **No agent mTLS:** verify the certificate reaches the native TLS listener, not an HTTP-only proxy.

### Internet connection DNS and backfill

Migration 103 creates the retained connection index and external-peer cache. The API server runs bounded backfill and reverse-DNS workers automatically. Configure local IPv4/IPv6 CIDRs in Server config. `INTERNET_DNS_SERVERS`, `INTERNET_DNS_POSITIVE_HOURS`, `INTERNET_DNS_NEGATIVE_HOURS`, `INTERNET_DNS_TIMEOUT_MS`, `INTERNET_DNS_CONCURRENCY` and `INTERNET_PEER_RETENTION_DAYS` control optional DNS behavior. See [defaults, limits and lifecycle](INTERNET_CONNECTIONS.md). Restart the API after environment changes.
