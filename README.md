![Header](assets/headerWinFire.png)

# WinFire Secure
Micro-Segmentation made easy. Why pay expensive vendors like Cisco, CrowdStrike, or Zero Networks for zero trust when it can be done for free...

WinFire is a control plane for Windows Firewall policy authoring, inventory, verification, log review, and identity segmentation configuration. This repository is an early implementation, **not a completed enforcement product**.


### Multi-user control plane
- Owner/Admin/Policy Editor/Auditor role model with resource-scoped permissions per policy, node group, and credential.
- Team creation and membership management; user profiles with per-user theme and notification preferences.
- Argon2 password verification, optional TOTP login, JWT access tokens with rotating refresh tokens, immediate session revocation, login rate limiting and account lockout.
- Immutable security audit log of every action ("who changed what and when") for compliance and reporting.

### Credential vault
- Envelope encryption at rest; passwords are write-only after save and never returned to the UI.
- Local and domain credential types, private or team visibility, assignment to nodes or node groups, and priority-ordered candidate credentials per node.
- One-click credential test against a node before anything is applied.

### Node inventory and agentless management
- Discover and onboard nodes by IP/FQDN; automatic detection of the working remote management transport; agentless and agent connection modes per node.
- Live collection of host facts (OS version/build, machine model/serial, firewall service status), forward and reverse DNS lookups, and management port probes.
- Remote, agentless firewall rule management (push desired state, read live state) with connection health checks, retries, and unreachable-node alerting.
- OS-version-aware command dialects so older Windows versions are managed with the correct interface.

### Policy authoring and version control
- Visual drag-and-drop policy builder: allow/deny rules, port/program groups, remote-address groups, profile scopes, schedule windows, and MFA gate nodes wired into a rule precedence graph.
- Compile the graph into concrete firewall rules, tagged and scoped per policy so apply/rollback is safe and reconciliation never touches unrelated rules.
- Conflict detection when two assigned policies contradict on the same node.
- Immutable, versioned policy snapshots: review diffs between versions, and recall any prior version in one click, which re-triggers apply on all assigned nodes.
- Draft buffer so in-progress edits survive a refresh without polluting version history.
- Audited apply runs showing the rule diff, per-node result, and error detail.

### Policy verification
- TCP-based allow and deny checks against assigned policies, with explicit pass/fail/inconclusive evidence (a managed deny-rule confirmation distinguishes "blocked by our rule" from "unreachable").
- On-demand "verify now" per policy or node plus scheduled sweeps; results feed drift detection and the compliance dashboard.

### Reporting
- Node inventory, DNS (forward/reverse with mismatch flags), policy coverage, verifier results, trending dashboards, and compliance reports.
- CSV and PDF export for audit hand-off.

### Firewall logs and learning mode
- Firewall and logon event collection from managed nodes with a searchable UI (filter by node, action, port, protocol, direction, time range).
- Learning sessions: capture observed traffic during a window, auto-propose a least-privilege policy, hand it to an operator for review and approval, then apply and enforce.
- Retention and pruning policies for stored events.

### Identity segmentation and MFA
- Segment definitions scoping target app/port, session TTL, and MFA provider.
- MFA challenge records and audit trail for every gate decision (who, what, when, result).
- Logon-rights baseline reading for managed nodes (which accounts can log on how — remote interactive, network, batch, service).
- Agentless just-in-time MFA path: out-of-band challenge (email/push/browser/Authenticator via Entra), temporary logon-right grant plus time-limited reactive firewall rule (default 4h), auto-expiry reverting to deny.
- Agent-based MFA gate (WinDivert/WFP-class interception) for interactive prompts and arbitrary application/port gating.
- RPC filter hardening: deny lateral-movement primitives (DCSync, WMI, PsExec, PetitPotam, ZeroLogon) at the RPC interface/opnum level.

### Agent distribution and remote enforcement
- Enrollment tokens, downloadable installer and one-line bootstrap for agent-mode nodes, service installation, certificate-based node identity, and push/pull communication.
- Secure remote access posture: per-node certificates, short-lived rotation, fail-closed MFA defaults with an explicit audited break-glass override.

### Platform behavior
- Single-port deployment (API and UI) with strict CORS; everything behind one reverse-proxy-terminated TLS origin.
- Scheduled background jobs (verifier sweeps, event collection, learning timers) with configurable intervals.
- Data persisted to a versioned database with an encryption-key file; the record store is excluded from source control.

## Run

Requires Node.js 20.19+ or 22.12+ (Node 24 recommended) and npm 11+.

```bash
npm ci
npm start
```

`npm start` builds the Vue app, starts Express, serves the UI and `/api/v1` on the same `PORT` (default 3000), and creates `data/winfire.db` and `data/secrets.json` on first run. Knex applies schema migrations before the API listens. The first run prints a random owner password to the terminal. To choose credentials, set `BOOTSTRAP_EMAIL` and `BOOTSTRAP_PASSWORD` before the first start. Keep `data/secrets.json` backed up and private: losing it makes encrypted vault records and existing refresh tokens unusable. The data directory is ignored by Git.

For development, use `npm run dev:api` and `npm run dev:web` in separate terminals; Vite proxies `/api` to Express. Run `npm test` and `npm run build` before deployment.

On Linux, run `npm run setup:winrm` once to install the Python WSMan transport in `.venv`. The Docker image includes this transport and `rpcclient`. On Windows, the connector uses PowerShell remoting directly. The Python transport follows the [pywinrm project](https://github.com/diyan/pywinrm) because [Microsoft does not support WSMan remoting from current non-Windows PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/wsman-remoting-in-powershell).

## Current capabilities

- Owner bootstrap, Argon2 password verification, optional TOTP login, JWT access tokens, rotating refresh tokens, immediate session revocation after password changes or admin action, protected owner role, invitations, role gates, login rate limits and account lockout.
- Envelope encrypted credential records with write-only passwords; node inventory, DNS lookups and connection port probes.
- Account profile avatars stored outside the database with PNG, JPEG and WebP signature and size checks.
- Vue Flow policy authoring, live port/address/program validation, connected port/address/profile scopes, local and remote port rules, immutable versions, graph and rule diff, recall, node and group assignment conflict checks, audited apply runs, read-only WinRM drift checks, and a remote PowerShell WinRM adapter. Schedule and MFA Gate nodes are rejected at compile time until their enforcement services exist.
- TCP based verifier with pass/fail/inconclusive evidence, managed deny-rule confirmation, coverage/inventory/compliance/verification reports with CSV/PDF exports, dashboard, log search and WinRM Security event pull.
- Learning sessions that propose a policy version for operator review and require explicit approval before application; segment and MFA challenge records; logon-rights baseline read; C# agent enrollment, certificate renewal, revocation, queued policy jobs, and Security event shipment with a persisted cursor.
- Hourly scheduled verifier and drift sweeps plus WinRM event pulls for configured nodes; adjust with `SWEEP_INTERVAL_MINUTES`. Transient transport errors move nodes through degraded and unreachable states with retry backoff; scheduled checks retry when the backoff expires. Agent nodes report drift as unknown until agent firewall readback is implemented.

## Windows connector requirements

The remote adapter uses Python `pywinrm` on Linux and `pwsh` on Windows to call `NetSecurity` and `Get-WinEvent` on the target. It needs a trusted Windows account with rights to read and manage firewall rules and read the Security log. Use a dedicated least privilege service account or gMSA scoped to the managed hosts. Do not use Domain Admin for routine access. Target WinRM, firewall rules, and PowerShell remoting must be configured by the operator. A port probe only shows an open management port; authenticated access is verified when facts are collected. HTTPS certificate validation is enabled by default; `WINRM_TLS_VERIFY=false` is available only for a controlled test host with a self-signed listener.

The app was built on Linux. Live WMI/DCOM firewall operations and netsh-over-remote-shell fallback are **not implemented** in this build. The available Windows Server 2022 test host at `192.168.250.6` now exposes WinRM on TCP 5985. A temporary encrypted credential was used to collect system facts, page Security events, add scoped inbound and outbound rules for documentation address `192.0.2.1` and unused ports, verify their local and remote ports, replace the outbound port, and remove both through three audited policy apply runs. The remote group was empty after cleanup. The temporary database was deleted. The read-only `secedit` logon-rights export timed out, and WMI/DCOM still needs validation. No password for that host was stored in the repository.

## Safety and deployment

Use HTTPS at the deployment edge and set a strict `CORS_ORIGIN` if the UI is served from another origin. The UI uses bearer tokens, not cookies. Protect the `data` directory and configure backups for the database and encryption key file. `npm start` uses one Express port for API and UI; a reverse proxy can terminate TLS on the same public origin.

Policy changes are scoped by the `WinFireSecure:<policyId>` group. Review compiled rules before applying. The verifier checks TCP reachability from the control plane and checks for a matching managed deny rule where possible. An unreachable target or an unconfirmed deny is recorded as inconclusive; the check still cannot prove which device dropped a packet.

See [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) for the plan items that still need engineering and live validation.

Invitations can be created from Administration. With `SMTP_HOST`, `SMTP_FROM`, and `PUBLIC_BASE_URL` configured, the server emails a seven-day link over TLS. Without SMTP it returns a one-time link to the admin for manual delivery. The invite token is stored only as a hash and is consumed once. Manual delivery does not mark the account email as verified. SMTP delivery has not been tested against a real mail server.

Changing an account email requires SMTP: the current address stays active until a one-day verification link sent to the new address is consumed. Verification revokes existing sessions. Accounts created from manually delivered invites can request verification once SMTP is configured.

## Agent development

The agent source is in `agent/WinFire.Agent`. `npm run build:agent` publishes a self-contained Windows x64 executable. It is unsigned until an operator signs it. The installer `agent/Install-WinFireAgent.ps1` refuses unsigned binaries, enrolls with a short-lived token supplied through stdin, stores the private key in the Windows machine certificate store, and installs an auto-start Windows Service. Its `EventLogWatcher` wakes a cursor-based Security log reader; batches are acknowledged over mTLS before the cursor advances, so retries are deduplicated by node and record ID. This path builds and passes API integration tests, but has not run on Windows. A signed MSI, signed self-update path, and live Windows validation remain to be built.

Agent enrollment requires the Express server to run HTTPS directly. Set `TLS_CERT` and `TLS_KEY` to a server certificate and key trusted by Windows clients, and set `AGENT_CA_CERT`, `AGENT_CA_KEY`, and `AGENT_CA_PASSPHRASE` to a dedicated client-certificate CA. Production startup rejects an unencrypted agent CA key. Keep its encrypted key outside the database and container image; provide the passphrase through a secret manager. All four certificate paths must be configured together. The same Express port then serves the UI, API, and mTLS agent routes. The server requests client certificates but only agent routes require one; each agent request checks its registered certificate fingerprint and revocation state.

For a test CA, create an encrypted key and certificate outside the repository:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass env:AGENT_CA_PASSPHRASE -out /secure/agent-ca.key
openssl req -new -x509 -key /secure/agent-ca.key -passin env:AGENT_CA_PASSPHRASE -out /secure/agent-ca.crt -days 365 -subj '/CN=WinFire Agent Test CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
```

The server certificate should be issued by a CA trusted on the Windows nodes. To test enrollment, create a node and token in Administration, then run the signed installer from an elevated PowerShell session with the published executable and server URL. The token expires after 15 minutes and cannot be reused. The Windows agent polls for policy jobs every 30 seconds; push, event streaming, and MFA gating are not yet implemented.
