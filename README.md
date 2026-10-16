# SoftEther Web Admin

A standalone web dashboard for an existing SoftEther VPN Server, with a responsive interface, server-side authentication, audited user management, and OpenVPN downloads.

This is an independent project, not an official SoftEther component. It does not install or replace SoftEther VPN Server.

## Features

- Server health, virtual hubs, active sessions, listeners, and protocol status.
- Create password-authenticated users; reset passwords while preserving account metadata; delete users with typed confirmation.
- Download a remote-access OpenVPN profile or public server certificate.
- Verified TLS between the console and SoftEther, server-side sessions, origin and CSRF checks, login throttling, and a fixed RPC allowlist.
- Non-root Docker deployment with a read-only filesystem, loopback-only web port, and persistent audit storage.

## Requirements

- An existing SoftEther server exposing its JSON-RPC API on a private network.
- Docker with Compose, a private Docker network reaching SoftEther, and an HTTPS reverse proxy.
- Node.js 24 and pnpm 11.25.0 for local development.
- Python 3 only for the optional interactive provisioning helper; the application runs on Node.js.
- A verified public server certificate and the matching TLS certificate name.

## Configure and run

1. Copy `.env.example` to `.env`. Set your HTTPS origin, private SoftEther address, certificate name, public VPN hostname, existing Docker network, and exact trusted proxy address. Resolve a Node 24 Alpine image digest and replace the image placeholder. All supplied domains and the documentation IP address are examples.
2. Obtain the public server certificate through a trusted administrative channel and verify it independently. Never supply a private key. For this deployment model, use the server's self-signed certificate as the trust anchor.
3. Run the provisioning helper on a host that can reach the private API. It prompts for the current server administrator password and a console password of at least 10 characters, verifies TLS/authentication, and writes local secret files. Passwords are not command-line arguments.

   ```sh
   sudo python3 scripts/provision.py --host PRIVATE_SERVER_ADDRESS --tls-name CERTIFICATE_NAME --ca-file /path/to/public-server.crt
   ```

4. Prepare audit storage and start the console:

   ```sh
   sudo install -d -m 0750 -o 1000 -g 1000 audit
   docker compose config --quiet
   docker compose build
   docker compose up -d
   ```

5. Route the configured HTTPS origin through your reverse proxy to the console's loopback port 3080. Pass the correct Host and X-Forwarded-Proto headers and configure the proxy source exactly in `TRUSTED_PROXIES`. A proxy on another machine requires a separately secured private route or tunnel. Do not expose the SoftEther management API publicly.
6. Sign in as `admin` with the console password chosen during provisioning.

Secret files live in `secrets/` and are excluded from Git and Docker build context. The helper uses a root-only parent directory and read-only files that Docker mounts for the non-root application. Never commit secret files, runtime audit logs, account exports, deployment backups, certificates, or downloaded profiles.

## Using the dashboard

Under **Users**, select a hub and choose **Add user**. New accounts use password authentication, no group, no expiry, and no custom policy. Password reset preserves group membership, expiry, and policies. Deleting a user prevents future login but may leave existing sessions connected.

Under **Protocols**, download an OpenVPN profile and import it into an OpenVPN 2.5+ compatible client. Authenticate with `username@hub` and the VPN user's password. The profile embeds the public certificate; it contains no passwords or private keys. The public-certificate button provides the certificate separately.

OpenVPN must already be enabled on UDP 1194 and reachable through the server's firewall and container networking. This console does not enable protocols or change firewall rules. The profile uses AES-128-CBC/SHA1 to match the supported SoftEther sample and verifies the configured certificate name. Other ports, certificate-chain deployments, and cipher modernization require adaptation and validation.

## Development and checks

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm test
```

Tests use synthetic credentials and generate temporary certificates; they do not contact a production VPN. Transport tests require permission to bind a local loopback socket and an OpenSSL executable. The suite covers session security, origin/CSRF checks, certificate validation, bounded API responses, safe user mutations, and authenticated downloads.

## Boundaries

The console holds administrator-level SoftEther credentials on the server. Protect the host and reverse proxy accordingly. Sessions and login limits are held in process memory; use a single console instance. Concurrent changes made through other administration tools are not transactionally locked. After a timeout, refresh before retrying a user mutation because it may already have applied.

Dashboard collection is bounded and reports unavailable data explicitly. User-change audit records are rotated locally; this is not a full SoftEther log viewer or a tamper-proof external audit system. A successful download or network handshake does not establish that client authentication, DNS, or tunnel routing works; validate those from a client device.

No production configuration, deployment history, real account data, certificates, private keys, or screenshots are included in this repository. A public repository does not itself grant an open-source license; no license has been selected yet.


## Address visibility — 0.3.1

Active sessions now show VPN IP addresses learned by the hub, separately from the client source IP. IPs are matched by hub and session name; a session may have multiple addresses. “Not learned” means the hub has no current IP-table entry, while “Unavailable” means retrieval failed.

The IP assignments section shows SecureNAT DHCP leases with assigned address, device name and expiry. Leases can outlive sessions and do not identify a user by themselves. Learned session IPs can also come from static configuration or another DHCP server; they are not all SecureNAT assignments. Results remain bounded to 200 entries per table and 20 hubs, with warnings when data is unavailable or truncated.


## User connection status — 0.3.2

The Users table includes Online/Offline status based on active sessions in the selected hub, matched by username without case sensitivity. Multiple sessions still show a single Online status. Failed or malformed session enumeration shows Unavailable, never Offline. The selected user list refreshes with the dashboard every 30 seconds while visible, and when Refresh is clicked.


## Online user IP popup — 0.3.4

Click an Online badge to fetch the selected user's current VPN addresses. The dialog lists unique learned addresses joined to that user's active sessions in the selected hub. Multiple devices are combined; stale IP-table entries without a matching active session are excluded. Offline, unavailable and not-yet-learned results are shown explicitly. The dialog supports keyboard activation, Escape and a Close button.


## Full-name editor — 0.4.0

The Users table no longer displays the Access column. Edit opens a full-name-only dialog for password-authenticated users; the username is displayed as context and cannot be changed. The server rejects extra username-change fields. Full-name edits preserve password hashes, group, description, expiry and policy; authentication material stays server-side and out of the audit log. Accounts with unsupported authentication are not editable here.


## VNC links — 0.4.1

VPN addresses in Active sessions and the Online popup link to `vnc://` to launch a registered VNC application (such as macOS Screen Sharing). IPv6 addresses use brackets. The device opening the link must have VPN routing to the target, which must have VNC or Screen Sharing enabled. The browser may prompt to open the application. No remote credentials are embedded and the dashboard does not proxy VNC traffic.
