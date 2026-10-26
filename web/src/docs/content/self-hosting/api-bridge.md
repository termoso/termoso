---
title: API Bridge
description: Let Ansible, Terraform or a CMDB manage hosts in a vault over a REST API — without the server ever seeing plaintext. Free on the hosted cloud and on self-hosted servers.
---

The API Bridge is a small container you run **in your own infrastructure**. It holds the keys of the vaults you give it, exposes a Termius-compatible REST API for hosts and groups, encrypts everything locally and pushes only ciphertext through the ordinary sync API. To the server it is one more device.

> [!NOTE]
> The bridge runs on your side; nothing is hosted per user. It is offered by the hosted cloud at `app.termoso.dev` and by self-hosted servers unless the operator sets `TERMOSO_BRIDGES=false`.

## Setting it up

1. In the cabinet, open **API Bridge → New bridge**, name it and pick the vaults it may write to. The key pair is generated in your browser and each vault key is sealed to it there.
2. Download the credentials file. It is shown **once** and contains the bridge's private key and token.
3. Run the container next to your automation:

```bash
docker run -d --name termoso-bridge --restart unless-stopped \
  -p 127.0.0.1:8081:8080 \
  -v "$PWD/termoso-bridge.json:/etc/termoso/bridge.json:ro" \
  -e TERMOSO_BRIDGE_API_KEY="$(openssl rand -hex 32)" \
  ghcr.io/termoso/termoso-bridge:latest
```

With Docker Compose use the `bridge` profile: `docker compose -f deploy/docker-compose.yml --profile bridge up -d`.

## MCP server for AI assistants

`termoso-bridge mcp` serves the [Model Context Protocol](https://modelcontextprotocol.io)
over stdio with the same credentials file. Read-only by default (`list_vaults`,
`list_hosts`, `get_host`, `list_groups`, `sync`); add `--allow-write` for
host/group changes and `--allow-exec` for `ssh_exec`, which runs one
non-interactive command on a host with the identity stored in the vault.
Passwords and keys are never returned to the assistant, host keys are checked
against the pins synced in the vault, and revoking the bridge cuts the
assistant off. Config for Claude Desktop / Cursor:

```json
{
  "mcpServers": {
    "termoso": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v",
        "/path/to/bridge.json:/etc/termoso/bridge.json:ro",
        "ghcr.io/termoso/termoso-bridge",
        "mcp"
      ]
    }
  }
}
```

Full tool list and flags: `docs/API_BRIDGE.md` in the repository.

## Security

- Keep the port bound to localhost or set `TERMOSO_BRIDGE_API_KEY`; callers then send it as a bearer token.
- Revoking the bridge in the cabinet kills its token at once. After a vault key rotation, the bridge needs the new key re-sealed from the cabinet before it can write again.
- The server never receives host addresses, usernames, passwords or keys from the bridge — only ciphertext, like from any other device.

Full API reference: [docs/API_BRIDGE.md](https://github.com/termoso/termoso/blob/main/docs/API_BRIDGE.md).

## Gateway: hosts you cannot reach

Some hosts have no route from a laptop or a phone — a lab behind NAT, a VPC with no bastion, an office network. Run the bridge there as a **gateway**:

```sh
termoso-bridge gateway
```

It keeps one outbound WebSocket to your server (no inbound port, no VPN). When a member who shares a vault with the bridge opens a host of that vault marked *via gateway*, the app tunnels the SSH connection through the server to the gateway, which dials the host on its own network. Everything in between is the SSH transport itself, so the server relays ciphertext.

What the server knows: that *this member* connected to *this host id* in *this vault* through *this gateway* (audited as `gateway.connected`). Hosts are named by vault and entity id — the gateway resolves the address from the vault it already mirrors — so the server never learns an address or a port.

- **Scope.** A gateway serves exactly the vaults sealed to the bridge, to members who can open them; team policies apply (`connect.bridge` permission, keys-only, mandatory jump host and the rest).
- **Allow-list.** `TERMOSO_GATEWAY_ALLOW=10.0.0.0/8,db.internal` limits what the gateway dials (hosts, IPs, CIDRs). Empty means anything a vault names.
- **Online state.** `GET /api/v1/gateways` lists the gateways you can use and whether each one has pinged in the last 90 s; an offline gateway refuses connections immediately instead of hanging.
- **Several servers.** Frames cross API replicas over Redis like the multiplayer relay, so a gateway and a client may land on different instances.

The gateway is the same binary and credentials file as the REST bridge; run both if you also want the API. Mark a host as reachable through a gateway in its SSH settings (`gateway_id` on the SSH config).
