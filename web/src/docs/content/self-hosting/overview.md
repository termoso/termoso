---
title: Self-hosting overview
description: Run the Termoso server on your own machine — one Docker Compose file, PostgreSQL, Redis and S3-compatible storage.
---

The server is the same one that runs the free cloud. It stores only ciphertext, so self-hosting is about control and availability, not about trusting a different operator with your data.

## What runs

| Service    | Image                              | Keep?          | Purpose                                                                                                  |
| ---------- | ---------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------- |
| `api`      | `ghcr.io/termoso/termoso-server` | stateless      | REST and WebSocket API under `/api/v1`, the web cabinet and these docs on `/`. Runs migrations on start. |
| `postgres` | `postgres:18-alpine`               | **back it up** | Accounts, devices, teams, vaults, encrypted items, audit log                                             |
| `redis`    | `redis:8-alpine`                   | disposable     | Login handshakes, MFA codes, rate limits, realtime fan-out                                               |
| `rustfs`   | `rustfs/rustfs`                    | optional       | Encrypted session logs (any S3-compatible store works)                                                   |
| `caddy`    | `caddy:2-alpine`                   | certificates   | TLS with Let's Encrypt (Compose `proxy` profile)                                                         |

Images are published for `linux/amd64` and `linux/arm64`, so the same file runs on x86 servers and on 64-bit ARM (Raspberry Pi 4+, Ampere, Graviton).

## Quick start

```bash
git clone https://github.com/termoso/termoso.git && cd termoso
cp deploy/.env.example deploy/.env && $EDITOR deploy/.env
docker compose -f deploy/docker-compose.yml --profile proxy up -d --wait
curl -fsS https://termoso.example.com/readyz     # → ready
```

`--wait` returns once the API health check passes, i.e. after migrations. Without the `proxy` profile everything binds to `127.0.0.1` and you put your own reverse proxy in front.

## Connecting the apps

In any app choose **Sign in → Use another server** and enter your `TERMOSO_PUBLIC_URL`. Accounts on different servers are independent; the apps can be signed in to one server at a time, and the Local vault always stays available.

> [!WARNING]
> Use a publicly trusted certificate (Let's Encrypt is fine). The apps ship the Mozilla root store and do not consult the operating system's trust store, so a private CA is not accepted.

## Kubernetes

A Helm chart lives in `deploy/helm/termoso`: the API as a Deployment plus, by default, single-node Postgres, Redis and RustFS next to it; for production point it at managed services. Steps and values are in the [self-hosting guide](https://github.com/termoso/termoso/blob/main/docs/SELF_HOSTING.md#kubernetes-helm).

## Podman

The same stack ships as Podman Quadlet units in `deploy/quadlet/` for servers that run everything through systemd, rootful or rootless. See the [full self-hosting guide](https://github.com/termoso/termoso/blob/main/docs/SELF_HOSTING.md#podman-quadlet) for the steps.
