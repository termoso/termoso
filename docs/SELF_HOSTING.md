# Self-hosting Termoso

This guide covers running the Termoso server for real users: what each piece
does, how to put it on the internet, and how to keep it alive. For a
five-line quick start see the [README](../README.md#self-hosting); for how
the pieces fit together internally see [ARCHITECTURE.md](ARCHITECTURE.md).

Two equivalent packagings ship in [`deploy/`](../deploy):

| | Docker Compose | Podman Quadlet |
|---|---|---|
| File(s) | `deploy/docker-compose.yml` | `deploy/quadlet/*.container`, `.network`, `.volume` |
| Runtime | Docker Engine + Compose v2, or `podman compose` | Podman 5.x or 6.x driven by systemd (4.4 is the floor; 5.0+ for health-gated start-up, 5.6+ for `podman quadlet install`) |
| Lifecycle | `docker compose up/down/pull` | `systemctl start/stop`, `podman auto-update` |
| Good for | any Linux host, quickest path | servers that already manage everything through systemd, rootless deployments |

Both use the same images, the same `.env` and produce the same running
system. Pick one; do not run both against the same volumes.

`deploy/docker-compose.dev.yml` is **not** a deployment: it starts only the
backing services with fixed passwords for `cargo run`/`cargo test`.

## What runs

| Service | Image | State | Purpose |
|---|---|---|---|
| `api` | `ghcr.io/termoso/termoso-server` | none | REST + WebSocket API under `/api/v1`, web cabinet on `/`, SSH ID handles, Android asset links. Runs migrations at start. |
| `postgres` | `postgres:18-alpine` | **volume, back it up** | accounts, devices, teams, vaults, encrypted entities, audit log, avatars |
| `redis` | `redis:8-alpine` | volume (disposable) | login handshakes, MFA/approval codes, session cache, rate limits, cross-replica event fan-out |
| `rustfs` | `rustfs/rustfs:1.0.0` | volume | client-encrypted session logs, reached by clients through pre-signed URLs. [RustFS](https://github.com/rustfs/rustfs) is an Apache-2.0 S3-compatible store; any other S3-compatible store is a drop-in replacement — see [Scaling](#scaling). Stacks that still run the retired MinIO image: see [Migrating from MinIO](#migrating-from-minio). |
| `bridge` (optional) | `ghcr.io/termoso/termoso-bridge` | none | Termius-compatible REST API for automation — see [API_BRIDGE.md](API_BRIDGE.md) |
| `caddy` (Compose `proxy` profile) | `caddy:2-alpine` | volume (certificates) | TLS termination for the API and RustFS |

The `termoso-server` and `termoso-bridge` images are multi-architecture
(`linux/amd64` and `linux/arm64`), so the same Compose file works on x86_64
servers and on 64-bit ARM hosts (Raspberry Pi 4+, Ampere, Graviton).

Everything the server stores about vault contents is ciphertext the server
cannot open; what it *can* read is listed in the README's
[security model](../README.md#security-model). Losing Redis logs nobody out
permanently — pending logins and MFA codes are lost, sessions are re-read from
PostgreSQL. Losing PostgreSQL loses the deployment. Losing RustFS loses
recorded session logs only.

### Ports

All published ports bind to `127.0.0.1` by default (`TERMOSO_LISTEN` in
`.env` for Compose, `PublishPort=` in the Quadlet units). Nothing is reachable
from other machines until you either put a reverse proxy on the same host or
deliberately change the bind address.

| Port | Service | Expose? |
|---|---|---|
| 8080 | API + cabinet | through your reverse proxy as `TERMOSO_PUBLIC_URL` |
| 9000 | RustFS S3 | through your reverse proxy as `TERMOSO_S3__PUBLIC_ENDPOINT` (only if session logs are used) |
| 9001 | RustFS console | no; use an SSH tunnel |
| 8081 | API Bridge | no; it is an unauthenticated-by-design local API guarded by one shared key |
| 9090 | Prometheus metrics (`TERMOSO_METRICS__*`) | no |
| 80/443 | Caddy (`proxy` profile) | yes, from the internet |

## Configuration

The server reads `TERMOSO_*` environment variables (nested sections use
`__`); the complete annotated list is [`deploy/.env.example`](../deploy/.env.example)
and the source of truth is
[`crates/termoso-server/src/config.rs`](../crates/termoso-server/src/config.rs).
The server validates the configuration at start and refuses to run with an
invalid `TERMOSO_MASTER_KEY`, a non-URL `TERMOSO_PUBLIC_URL`, a partial SMTP
block or an unknown SSO kind.

Minimum for a useful instance:

```dotenv
TERMOSO_MASTER_KEY=            # openssl rand -base64 32 — back it up with the database
TERMOSO_PUBLIC_URL=https://termoso.example.com
POSTGRES_PASSWORD=             # openssl rand -hex 24
RUSTFS_ACCESS_KEY=termoso
RUSTFS_SECRET_KEY=             # openssl rand -hex 24
TERMOSO_S3__PUBLIC_ENDPOINT=https://s3.termoso.example.com
TERMOSO_ADMIN_EMAILS=you@example.com
TERMOSO_OWNER_EMAIL=you@example.com   # optional; default = first registered account
TERMOSO_SMTP__HOST=… PORT=… USERNAME=… PASSWORD=… SECURITY=starttls FROM=…
TERMOSO_TURNSTILE__SITE_KEY=… TERMOSO_TURNSTILE__SECRET_KEY=…   # optional Cloudflare Turnstile captcha
TERMOSO_DATA_REGION=eu-central            # optional label shown in /server/info and stamped on new teams
TERMOSO_TEAM_DELETION_GRACE_DAYS=7        # days before a requested team deletion is purged (0 = immediately)
- `TERMOSO_MIN_CLIENT_VERSION` — oldest client version allowed to sign in (semver). Default: the server's own version; older clients get `client_update_required` and are asked to update.
TERMOSO_AUDIT_RETENTION_DAYS_MAX=3650     # ceiling for per-team audit retention
TERMOSO_TEAM_IDP=true                     # allow teams to configure their own OIDC/SAML IdP
```

Corporate mode (one company per server) is switched on from the admin
settings rather than the environment: pick a *home team* (every account
joins it automatically), enable *SSO only* (password sign-in and e-mail
sign-up are refused; the bootstrap admin keeps password access so you cannot
lock yourself out) and, if wanted, hide personal vaults. Clients read all of
it from `/api/v1/server/info`. The compliance controls these settings map to
are listed in [COMPLIANCE.md](COMPLIANCE.md).

With Turnstile keys the server demands a captcha token for sign-up, account
recovery and repeated failed logins from one address. The web cabinet renders
the widget itself; the desktop and mobile apps load the server's `/captcha`
page (the widget alone, nothing else) when the server asks — only the
server's own hostname has to be allowed for the site key in Cloudflare.

Without SMTP the server still runs, but e-mail verification, device approval
by e-mail, e-mail MFA and team digests are off. Without `TERMOSO_S3__*` the
session-log feature is absent from the clients.

`TERMOSO_MASTER_KEY` wraps the server-side secrets (SSO client secrets, bridge
tokens, WebAuthn state). A database restored with a different master key is
unusable — store the key next to the backups.

### Reverse proxy and TLS

The API and cabinet share one origin; the cabinet is a single-page app served
with an `index.html` fallback by the server itself, so the proxy only needs
to forward everything, including WebSocket upgrades, to `api:8080` and set
`X-Forwarded-For` (the stack sets `TERMOSO_TRUST_PROXY=true`). The API takes
the *last* address in that header — the one your proxy appended — so a client
cannot spoof its IP for rate limits and security events. Never enable
`TERMOSO_TRUST_PROXY` on a server reachable without the proxy in front.

The Compose `proxy` profile does this with Caddy and Let's Encrypt:

```dotenv
TERMOSO_DOMAIN=termoso.example.com          # = host of TERMOSO_PUBLIC_URL
TERMOSO_S3_DOMAIN=s3.termoso.example.com    # = host of TERMOSO_S3__PUBLIC_ENDPOINT
ACME_EMAIL=you@example.com
```

```bash
docker compose -f deploy/docker-compose.yml --profile proxy up -d --wait
```

Both names must resolve to the host and ports 80/443 must be open. The
[`Caddyfile`](../deploy/Caddyfile) is two `reverse_proxy` blocks; adapt it to
nginx or Traefik if you already run one — the only requirements are HTTP/1.1
upgrade support for `/api/v1/ws` and that the storage hostname forwards to
RustFS unchanged (pre-signed URLs are signed for that exact host and path).

Optional second hostname: `TERMOSO_SSHID_URL` serves SSH ID public keys at the
root of a dedicated origin (`https://sshid.example.com/<handle>`), convenient
for `curl … | tee -a ~/.ssh/authorized_keys`. Point another proxy block at
`api:8080` with that hostname. `<public_url>/sshid/<handle>` keeps working;
browsers opening it are redirected to the dedicated origin, `curl` is not. Any
of these URLs opened in a browser (`Accept: text/html`) shows a page with the
install command, key types and fingerprints instead of the raw list.

### Landing page: on, off, or on its own domain

`/` of the cabinet origin is a public landing page by default. Two knobs
change that; both are plain environment variables, there is no admin switch.

| Layout | `.env` | Result |
|---|---|---|
| One origin (default) | `TERMOSO_PUBLIC_URL=https://termoso.example.com` | `/` is the landing, `/login`, `/account`, … the cabinet, `/api/v1` the API |
| No landing | `TERMOSO_LANDING=false` | `/` redirects to `/login` (a signed-in browser continues to the cabinet); nothing else changes |
| Landing on the apex, cabinet + API on a subdomain | `TERMOSO_PUBLIC_URL=https://app.example.com`<br>`TERMOSO_WEB_URL=https://app.example.com`<br>`TERMOSO_LANDING_URL=https://example.com` | `https://example.com/` is the landing, `https://app.example.com/` goes to `/login` |

In the split layout both hostnames point at the same server (one proxy block
with two addresses is enough — with the Compose `proxy` profile set
`TERMOSO_DOMAIN=app.example.com, example.com`); the server tells them apart
by `Host`. On the landing host only `/`, the static files, the health probes
and `/api/v1/server/info` are answered; every other path — `/login`,
`/signup`, `/invite/…`, `/join/…`, the SSO callback, the whole API — is a
`307` to the same path and query on `TERMOSO_WEB_URL`, so links in e-mails,
invitations, multiplayer links and Android App Links keep working whichever
hostname they were typed on. The landing's own buttons already point at the
cabinet origin. `TERMOSO_LANDING_URL` must be a bare origin, must differ
from `TERMOSO_PUBLIC_URL`/`TERMOSO_WEB_URL`, and needs `TERMOSO_WEB_DIR`
(the landing is part of the cabinet bundle) — the server refuses to start
otherwise. Everything else (`TERMOSO_WEBAUTHN__RP_ID`, OAuth redirect URIs,
`assetlinks.json`) stays tied to `TERMOSO_PUBLIC_URL`, i.e. the cabinet.

### Documentation: on, off, or on its own domain

The documentation ships inside the cabinet bundle at `/docs` and is served on
the landing origin too. `TERMOSO_DOCS=false` hides it (404). `TERMOSO_DOCS_URL`
(e.g. `https://docs.example.com`; with the Compose `proxy` profile add the
name to `TERMOSO_DOMAIN`) gives it a dedicated origin: that host answers
`/docs/*`, the static files and the health probes, `/` goes to `/docs`, and
`/docs/*` on the landing and cabinet origins redirects there. The same rules
as for `TERMOSO_LANDING_URL` apply: a bare origin, different from the other
hostnames, `TERMOSO_WEB_DIR` set.

### Search engines and link previews

The landing page and every docs page are served with their own `<title>`,
description, canonical URL and Open Graph / Twitter card (image `/og.png`),
rendered once at start-up from `seo.json` in the web bundle, so crawlers and
chat link previews see real metadata without running the app. Cabinet routes
(`/login`, `/vaults`, ...) carry `noindex, nofollow`. `/robots.txt` allows
everything on the landing and docs origins and disallows the cabinet origin
(except `/docs` when the docs live there); `/sitemap.xml` on the landing
origin lists the landing and all docs pages, using `TERMOSO_LANDING_URL` /
`TERMOSO_DOCS_URL` when set.

### WebAuthn, App Links, SSO

* `TERMOSO_WEBAUTHN__RP_ID` must be the registrable domain of
  `TERMOSO_PUBLIC_URL`; keep the `tauri://localhost,http://tauri.localhost`
  origins so the desktop app can use passkeys.
* `TERMOSO_ANDROID_APP_LINKS=<package>=<SHA-256>` publishes
  `/.well-known/assetlinks.json` so invitation and multiplayer links open in
  the Android app; the fingerprint is the one of the APK you distribute.
* SSO providers are configured as `TERMOSO_SSO__<slug>__*`. For OIDC the
  redirect URI to register with the IdP is
  `<TERMOSO_PUBLIC_URL>/api/v1/auth/sso/callback`. For SAML 2.0 (`KIND=saml`)
  set `SAML_METADATA` to the IdP metadata (an `https://` URL, a file path or
  inline XML) and register our SP with the IdP by pointing it at
  `<TERMOSO_PUBLIC_URL>/api/v1/auth/sso/<slug>/saml/metadata` — that
  document is also the SP `entityID`, and the Assertion Consumer Service is
  `<TERMOSO_PUBLIC_URL>/api/v1/auth/sso/saml/acs` (HTTP-POST). Responses must
  be signed with a certificate published in the IdP metadata; SHA-1 and
  PKCS#1 v1.5 key transport are refused unless `SAML_ALLOW_SHA1=true`. Give
  the SP its own certificate and key (`SAML_SP_CERTIFICATE`/
  `SAML_SP_PRIVATE_KEY`, PEM or paths) to sign `AuthnRequest`s and to receive
  encrypted assertions (RSA-OAEP + AES-CBC/GCM). See
  `deploy/.env.example` for the full variable list.
* **Use a publicly trusted certificate** (Let's Encrypt is fine). The Rust
  clients and the server's outgoing HTTPS ship the Mozilla root store
  (`webpki-roots`) and do not consult the OS trust store, so a private CA is
  not accepted by the desktop, Android or iOS apps.

## Docker Compose

```bash
git clone https://github.com/termoso/termoso.git && cd termoso
cp deploy/.env.example deploy/.env && $EDITOR deploy/.env
docker compose -f deploy/docker-compose.yml up -d --wait
curl -fsS http://127.0.0.1:8080/readyz     # → ready
```

`--wait` returns once the API health check (`termoso-server --healthcheck`,
which calls `/readyz`) passes, i.e. after migrations. Profiles:

```bash
docker compose -f deploy/docker-compose.yml --profile proxy  up -d   # + Caddy
docker compose -f deploy/docker-compose.yml --profile bridge up -d   # + API Bridge
```

The bridge needs `TERMOSO_BRIDGE_API_KEY` and the credentials file exported
from the cabinet at `TERMOSO_BRIDGE_CREDENTIALS_FILE` (default
`deploy/bridge.json`). Podman users can run the same file with
`podman compose`.

Pin the release you run with `TERMOSO_VERSION=0.2.0` rather than `latest`;
the tags match [GitHub releases](https://github.com/termoso/termoso/releases).

### Upgrading

```bash
git pull                                   # picks up compose/.env.example changes
$EDITOR deploy/.env                        # diff against deploy/.env.example
docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d --wait
```

Migrations are forward-only and run by the first API replica that starts;
they take a lock, so several replicas starting at once are safe. Read the
release notes before jumping several minor versions — a release that requires
manual steps says so.

The stack pins PostgreSQL by major version (`postgres:18-alpine`). A PostgreSQL
major upgrade is never automatic: the 18 image refuses to start on a 17 data
directory. Dump with the old image, then restore into the new one:

```bash
docker compose -f deploy/docker-compose.yml exec postgres pg_dump -U termoso -Fc termoso > pre-upgrade.dump
docker compose -f deploy/docker-compose.yml down
docker volume rm termoso_postgres          # or move it aside
# bump the image tag, then
docker compose -f deploy/docker-compose.yml up -d --wait postgres
docker compose -f deploy/docker-compose.yml exec -T postgres pg_restore -U termoso -d termoso --no-owner < pre-upgrade.dump
docker compose -f deploy/docker-compose.yml up -d --wait
```

Stacks created before the move to PostgreSQL 18 mounted the volume at
`/var/lib/postgresql/data`; the 18+ image keeps its data under
`/var/lib/postgresql/<major>/docker`, which is why the volume is now mounted
at `/var/lib/postgresql` (and why `pg_upgrade --link` works in place there).

### Migrating from MinIO

Stacks set up before 0.6.1 ran MinIO for session logs; its last community
image (`quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z`) has since been
withdrawn from the registry, so a fresh `pull` fails. The stack now ships
RustFS instead. To move over:

1. In `deploy/.env` rename `MINIO_ROOT_USER` → `RUSTFS_ACCESS_KEY`,
   `MINIO_ROOT_PASSWORD` → `RUSTFS_SECRET_KEY`, `MINIO_BUCKET` → `S3_BUCKET`,
   `MINIO_PORT`/`MINIO_CONSOLE_PORT` → `RUSTFS_PORT`/`RUSTFS_CONSOLE_PORT`
   (Quadlet: the same two credentials in `/etc/termoso/stack.env`, plus
   `TERMOSO_S3__ENDPOINT=http://termoso-rustfs:9000`, and replace the
   `termoso-minio.*` unit files with `termoso-rustfs.*`).
2. `docker compose -f deploy/docker-compose.yml up -d --wait` (or
   `systemctl daemon-reload && systemctl start termoso-rustfs termoso-api`).
   RustFS starts on a new, empty volume; the server creates the bucket on
   first use. The reverse-proxy hostname and `TERMOSO_S3__PUBLIC_ENDPOINT`
   stay as they are.
3. Existing logs live in the old `minio` volume, which is left untouched. If
   the old image is still in your local image cache, start it once alongside
   and mirror the bucket with any S3 client (`rclone sync`, `mc mirror`) into
   RustFS; otherwise those recordings can no longer be downloaded (their
   entries stay in the log list until deleted). Remove the old volume afterwards
   (`docker volume rm termoso_minio` / `podman volume rm termoso-minio`).

### Scaling

The API keeps no local state. Run more replicas behind a proxy that
load-balances them (drop the `ports:` mapping of `api` and let the proxy join
the Compose network, or run replicas on several hosts) and they share
sessions through PostgreSQL and realtime events through Redis pub/sub.
Periodic jobs (digests, retention) take a PostgreSQL advisory lock so only
one replica runs them; the webhook worker runs on every replica and claims
rows with `SKIP LOCKED`. Health-check replicas on `/readyz`; on `SIGTERM` a
replica answers 503 there for `TERMOSO_DRAIN_SECS` (default 3) before it
stops accepting connections.

PostgreSQL, Redis and RustFS are single instances in this stack;
replace them with managed services by pointing `TERMOSO_DATABASE_URL`,
`TERMOSO_REDIS_URL` and `TERMOSO_S3__*` elsewhere and removing the services
you no longer need. Any S3-compatible store works, including AWS S3
(`TERMOSO_S3__FORCE_PATH_STYLE=false`, no `ENDPOINT`). Redis Sentinel is
supported through `redis+sentinel://s1:26379,s2:26379/mymaster`; PgBouncer
must run in `session` mode. Topology, failure modes and the restore runbook:
[HA.md](HA.md).

## Podman Quadlet

[Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
turns the unit files in [`deploy/quadlet/`](../deploy/quadlet) into systemd
services at `daemon-reload`. You get `journalctl`, `systemctl status`,
automatic restarts and optional unattended image updates, with no long-running
daemon.

```
termoso.network              private network, containers resolve each other by name
termoso-{postgres,redis,rustfs}.volume
termoso-{postgres,redis,rustfs,api}.container
termoso-bridge.container.example   rename to .container to enable the bridge
stack.env.example            in-stack addresses + credentials → /etc/termoso/stack.env
bridge.env.example           bridge key → /etc/termoso/bridge.env
```

The API reads two environment files: `/etc/termoso/env` (your filled-in copy
of `deploy/.env.example`, identical to the Compose `.env`) and then
`/etc/termoso/stack.env` (container addresses; it overrides the database, Redis
and S3 settings just like the Compose file does). Compose interpolates the
passwords into the URLs for you; with Quadlet you write them in `stack.env`
yourself — the example file marks every place.

### Rootful (system services)

On Podman ≥ 5.6 the unit files can be installed with
`sudo podman quadlet install deploy/quadlet/*.{container,network,volume}`
(`podman quadlet list` / `rm` manage them afterwards); the manual copy below
works on every supported version.

```bash
sudo install -d -m 0750 /etc/termoso
sudo install -m 0600 deploy/.env                    /etc/termoso/env
sudo install -m 0600 deploy/quadlet/stack.env.example /etc/termoso/stack.env
sudo $EDITOR /etc/termoso/stack.env                 # passwords (twice each)
sudo cp deploy/quadlet/*.{container,network,volume} /etc/containers/systemd/
sudo systemctl daemon-reload
sudo systemctl start termoso-api                    # pulls deps via Requires=
sudo systemctl status 'termoso-*'
journalctl -u termoso-api -f
```

Generated units cannot be `systemctl enable`d by hand; their
`[Install] WantedBy=default.target` section is honoured by the generator, so
they start at boot as soon as the files are in place. Stop everything with
`systemctl stop termoso-api termoso-postgres termoso-redis termoso-rustfs`;
remove the files and `daemon-reload` to retire the stack (volumes stay until
`podman volume rm`).

### Rootless (user services)

Rootless Podman gives every container an unprivileged user namespace; port
8080 and above bind fine without root. The unit files are the same, the paths
change:

```bash
mkdir -p ~/.config/containers/systemd ~/.config/termoso
install -m 0600 deploy/.env                      ~/.config/termoso/env
install -m 0600 deploy/quadlet/stack.env.example ~/.config/termoso/stack.env
sed -i "s#/etc/termoso/#$HOME/.config/termoso/#" deploy/quadlet/*.container
cp deploy/quadlet/*.{container,network,volume} ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start termoso-api
loginctl enable-linger "$USER"     # keep user services running after logout
```

Rootless containers cannot bind ports below 1024, so terminate TLS with a
system-level proxy (or lower `net.ipv4.ip_unprivileged_port_start`) and point
it at `127.0.0.1:8080`. Rootless networking through pasta costs some
throughput on large SFTP-log uploads; that is the only functional difference.
Podman 6 dropped slirp4netns, cgroups v1, iptables and CNI; hosts that still
rely on any of those stay on Podman 5.x (the units do not depend on either).

### Health, restarts and updates

Every container declares a health check; with Podman ≥ 5.0 `Notify=healthy`
makes a unit *active* only once its check passes, so `termoso-api` waits for
PostgreSQL, Redis and RustFS to be genuinely ready. On Podman 4.x the
dependencies are still ordered, but the API may start a few seconds early and
be restarted by systemd (`Restart=always`, 5 s) until the database answers.
Both behaviours converge on a healthy stack.

To upgrade, change the image tag in `termoso-api.container` (and the bridge
file), then `systemctl daemon-reload && systemctl restart termoso-api`. Or
uncomment `AutoUpdate=registry` and enable `podman-auto-update.timer` to let
Podman pull new images and restart the affected units nightly — reasonable
only if you follow a pinned tag such as `0.2`, not `latest`.

Validate edited unit files without touching the system:

```bash
/usr/libexec/podman/quadlet -dryrun -user   # path varies: /usr/lib/podman/quadlet on some distros
```

## Kubernetes (Helm)

`deploy/helm/termoso` runs the API as a Deployment (read-only, non-root,
`termoso-server --healthcheck` as liveness/readiness probe) and, by default, a
single-replica Postgres, Redis and RustFS as StatefulSets with persistent
volumes, the same images as the compose stack:

```sh
helm install termoso deploy/helm/termoso --namespace termoso --create-namespace \
  --set secrets.TERMOSO_MASTER_KEY="$(openssl rand -base64 32)" \
  --set config.TERMOSO_PUBLIC_URL=https://termoso.example.com \
  --set config.TERMOSO_WEBAUTHN__RP_ID=termoso.example.com \
  --set config.TERMOSO_ADMIN_EMAILS=you@example.com \
  --set bundled.postgres.password="$(openssl rand -hex 16)" \
  --set bundled.rustfs.secretKey="$(openssl rand -hex 16)" \
  --set ingress.enabled=true --set ingress.hosts[0].host=termoso.example.com
```

Every `TERMOSO_*` variable from `deploy/.env.example` goes under `config`
(plain) or `secrets` (rendered into a Secret; or bring your own with
`existingSecret`). For production turn `bundled.*.enabled` off and point
`database`, `redis` and `s3` at managed services, then `replicaCount` can go
above one (see [Scaling](#scaling)). `metrics.enabled` exposes the private
Prometheus listener and `metrics.serviceMonitor.enabled` adds a ServiceMonitor.
Upgrade with `helm upgrade termoso deploy/helm/termoso --reuse-values --set
image.tag=<version>`; migrations run on start.

## Backups and restore

Back up, in this order of importance:

1. **PostgreSQL** — the deployment.
2. **`TERMOSO_MASTER_KEY`** (in `.env`) — without it the database is only
   partially usable.
3. **RustFS data** — session logs, if you care about them (or turn on bucket
   versioning instead).
4. The `.env` file itself.

Redis holds nothing worth keeping.

The `backup` profile ships `termoso-server backup|restore|backup-check` next
to `pg_dump`/`pg_restore` 18 and `age`:

```bash
# Compose — nightly from cron or a systemd timer
docker compose -f deploy/docker-compose.yml --profile backup run --rm backup
#   → ./backups/termoso-20261018T020000Z.dump + .manifest.json
# verify a file against this server (checksum, schema, master key), no DB access
docker compose -f deploy/docker-compose.yml --profile backup run --rm backup \
  backup-check --from /backups/termoso-20261018T020000Z.dump

# Quadlet / bare metal: same binary, pg_dump of the server's major on PATH
TERMOSO_DATABASE_URL=… TERMOSO_MASTER_KEY=… termoso-server backup --out /var/backups/termoso

# session logs (skip when the bucket is versioned)
docker run --rm -v termoso_rustfs:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/termoso-logs-$(date +%F).tgz -C /data .
```

Set `TERMOSO_BACKUP_AGE_RECIPIENT=age1…` in `.env` (`age-keygen` makes the
pair) to get `age`-encrypted dumps; keep the identity file with the master
key, not with the dumps. Dumps contain e-mail addresses, team structure and
ciphertext that a future key compromise could unlock.

The manifest next to each dump records the server version, schema version,
master-key fingerprint, row counts and SHA-256. `restore` refuses a dump
from a newer schema or a different master key, runs `pg_restore --clean`,
applies newer migrations and compares row counts:

```bash
docker compose -f deploy/docker-compose.yml stop api
docker compose -f deploy/docker-compose.yml --profile backup run --rm backup \
  restore --from /backups/termoso-YYYYMMDDTHHMMSSZ.dump --yes   # [--age-identity /backups/key.txt]
docker compose -f deploy/docker-compose.yml up -d --wait
```

Restoring an older dump into a newer version works; the reverse does not
(`restore` tells you which image to install first). Rehearse with
`deploy/restore-test.sh <dump>` — it restores into a throwaway stack and
checks the API comes up.

## Monitoring

* `GET /healthz` — process is up. `GET /readyz` — JSON with `pg`, `redis`, `s3`, `draining`; 503 while any is false. PostgreSQL and Redis
  answer. Both are unauthenticated and cheap.
* `TERMOSO_METRICS__ENABLED=true` exposes Prometheus metrics on a **separate**
  listener (`TERMOSO_METRICS__BIND`, default `127.0.0.1:9090`) that is never
  published by the stack. Scrape it from the host or over a private network.
* Logs go to stdout as text or JSON (`TERMOSO_LOG_FORMAT`). The server never
  logs credentials, session tokens, keys or vault contents; `TERMOSO_LOG`
  takes a `tracing` filter (`info,sqlx=warn` is a sane production level).

## Development stack

```bash
docker compose -f deploy/docker-compose.dev.yml up -d --wait
cargo run -p termoso-server            # http://localhost:8080, Swagger UI at /api/docs
cargo test --workspace                 # integration tests use the same services
docker compose -f deploy/docker-compose.dev.yml down -v   # wipe
```

It publishes PostgreSQL (`termoso`/`termoso`), Redis, RustFS
(`minioadmin`/`minioadmin`) and [Mailpit](https://mailpit.axllent.org)
(SMTP on 1025, inbox UI on <http://localhost:8025>) on localhost only. Data
persists in named volumes across restarts. Do not expose it, do not reuse its
passwords, and do not point a production `TERMOSO_DATABASE_URL` at it.

## Limitations

* One region, one PostgreSQL: there is no multi-primary or read-replica
  support in the server.
* RustFS in the stack is a single node; use replicated storage for anything
  you cannot afford to lose.
* The API Bridge exposes hosts and groups only, and holds the keys of the
  vaults it was granted — treat its host as part of those vaults' trust
  boundary.
* SAML is SP-initiated sign-in only: no IdP-initiated responses, no Single
  Logout, no artifact binding. Signing in through SAML (like OIDC) proves the
  e-mail; the vault password is still required, so the IdP never holds vault
  key material.
* Private certificate authorities are not supported by the clients (see
  above); the server must present a chain that validates against the Mozilla
  root store.
