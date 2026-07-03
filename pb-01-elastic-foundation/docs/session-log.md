# PB-01 — Session Log: Elastic Foundation

Build and troubleshooting record for the first major session of **PB-01 (Elastic Foundation)**.
This is a working log, not a polished deliverable — it captures what was built, the decisions
made, and the problems hit (and how they were solved) so the reasoning survives beyond memory.

---

## Infrastructure (final state)

| Item | Value |
|------|-------|
| Provider | Hetzner Cloud |
| Server type | CX33 (4 vCPU x86 Intel/AMD, 8 GB RAM, 80 GB SSD) |
| Location | Nürnberg (`eu-central`) |
| OS | Ubuntu 24.04 LTS |
| Public IPv4 | `178.104.26.65` |
| Hostname | `prismbox-pb01` |
| Admin tunnel | WireGuard — server `10.10.10.1` ↔ host `10.10.10.2` |
| Docker | Engine 29.6.1, Compose v5.2.0 (official Docker apt repo) |
| Elastic Stack | Elasticsearch + Kibana `9.4.2`, single-node, security + TLS on ES layer |

> Note: server was originally targeted at Helsinki, then Falkenstein — CX33 availability
> shifted between locations mid-provisioning (limited-availability tier). Landed in Nürnberg,
> which is fine (mature DC, lower latency to Bremen).

---

## Security posture

- **SSH:** key-only auth (ed25519), no password login. Root password email disabled at creation.
- **Hetzner Cloud Firewall** (`pb-01-baseline`), inbound rules:
  - TCP 22 (SSH)
  - ICMP (ping)
  - UDP 51820 (WireGuard)
  - Outbound: unrestricted (needed for apt / Docker pulls)
- **Elasticsearch & Kibana bound to the WireGuard interface only** (`10.10.10.1:9200`,
  `10.10.10.1:5601`). Physically unreachable from the public internet — reachable only
  through the tunnel.
- **TLS enabled on the Elasticsearch layer** (self-generated CA, node cert with `10.10.10.1`
  in the IP SANs). Auth (`xpack.security`) enabled.

---

## Build steps (summary)

1. Provisioned CX33, Ubuntu 24.04, SSH key added at creation.
2. `apt update && apt upgrade -y`, reboot on a clean slate.
3. Installed Docker Engine + Compose plugin from the **official Docker apt repo**
   (not the outdated Ubuntu `docker.io` package).
4. Installed and configured **WireGuard** (see troubleshooting below — this took the longest).
5. Set `vm.max_map_count=262144` (persisted in `/etc/sysctl.d/99-elasticsearch.conf`) —
   Elasticsearch refuses to start without it.
6. Deployed Elastic stack via `docker-compose.yml` with a `setup` cert-generation container,
   `es01` (heap capped `-Xms2g -Xmx2g`, 3 GB container limit), and `kibana` (1 GB limit).
7. Verified ES over HTTPS returns cluster JSON; logged into Kibana over the tunnel.

Working directory on server: `/opt/prismbox/elastic/` (`.env`, `docker-compose.yml`).

---

## Troubleshooting log (the useful part)

### 1. WireGuard — "Invalid MAC of handshake" (the big one)

**Symptom:** tunnel would not come up. Client sent handshake packets, they *arrived* at the
server (confirmed via `tcpdump`), but `wg show` on the server showed **no handshake, no
transfer**. Kernel log (`dmesg`) eventually revealed the specific error:

```
wireguard: wg0: Invalid MAC of handshake, dropping packet from <client-ip>
```

**What it means:** "Invalid MAC of handshake" is cryptographically specific. The handshake
initiation carries a `mac1` field keyed on the **responder's (server's) public key**. The
server recomputes it with its own public key and checks the match. Failure = the initiator
signed the packet using a server public key that doesn't match the server's real key.
**It is always a key mismatch — not a firewall, NAT, or routing problem.**

**Dead ends ruled out (each by direct evidence):**
- Hetzner Cloud Firewall — UDP 51820 rule confirmed applied.
- Local `ufw` — inactive.
- `iptables` / Docker chains — INPUT policy `ACCEPT`, Docker chains only touch `docker0`.
- `rp_filter` — not the cause.
- Clock skew — both ends NTP-synced.
- CGNAT — ruled out; source port was **stable** across packets (`3137`), which is what a
  healthy CGNAT mapping looks like. Unstable/rotating source ports would be the problem case.
- NetworkManager `wg0` profile — appeared as `connected (externally)` but the saved profile
  didn't actually exist (delete failed with "unknown connection") → NM was only *tracking* a
  `wg-quick`-created interface, which is harmless.

**Root cause (best-supported):** the key material used by the **live kernel interface** had
diverged from the key material on **disk**. Across many `nano` edits + copy-paste rounds +
key regenerations, the config file could pass every `grep`/`diff` check while the running
interface still held a stale key from an earlier `wg-quick up`.

**KEY LESSON:**
- `wg-quick up` loads the config into the kernel **once**. Editing `wg0.conf` afterward
  changes the file but **NOT** the live interface.
- `wg show` reports **kernel state**, not file state. It is the source of truth for what's
  actually running.
- After *any* edit to `wg0.conf`, reload the live interface:
  - Hot reload: `wg syncconf wg0 <(wg-quick strip wg0)`
  - Full cycle: `wg-quick down wg0 && wg-quick up wg0`

**Fix:** stopped bisecting the accreted config. Did a **clean deterministic rebuild** —
regenerated both keypairs from scratch and wrote each config via a single `heredoc` with
`PrivateKey = $(cat ...private.key)` so no key was ever hand-typed within a machine. Only the
peer **public** keys were pasted across (public keys are safe to share; private keys never
leave their machine). Tunnel came up on first try: `latest handshake` present, 0% packet loss.

**OPSEC note:** private keys were briefly exposed in screenshots earlier in the session and
were **rotated** afterward — the live keys were never shown anywhere. Only public keys are
ever shared. `wg pubkey < privkey` derives the public key without exposing the private one.

### 2. Kibana — `ERR_SSL_PROTOCOL_ERROR` on `https://10.10.10.1:5601`

**Symptom:** browser refused the connection ("sent an invalid response").

**Cause:** TLS was enabled on the **Elasticsearch** layer (9200) but **not** on Kibana's own
web server (5601). Kibana serves plain **HTTP**; the browser tried HTTPS → handshake failed.

**Resolution:** access Kibana over **`http://10.10.10.1:5601`** (note: `http`). This is *not*
an exposure — the host↔server path is already encrypted by WireGuard, so credentials/session
are protected in transit at the network layer. Encrypt-once-at-the-tunnel is a legitimate
architecture for a tunnel-only service.

**Deferred item:** enabling TLS on Kibana's web layer (defense-in-depth, encryption at both
tunnel *and* application layer) is a known follow-up — a good fit for the PB-03 hardening pass.

### 3. Kibana login — "Username or password is incorrect"

**Cause:** when copying the `elastic` password out of `.env` via `grep`, a leading `=`
(the `KEY=value` delimiter) was accidentally included in the copied value.

**Fix:** strip the prefix — `grep ELASTIC_PASSWORD .env | cut -d'=' -f2` returns only the
value. Username is `elastic`. Password lives in `/opt/prismbox/elastic/.env` (chmod 600).

---

## Known deferred items (carry into later PB-01 sessions / PB-03)

- [ ] TLS on Kibana's web server layer (currently HTTP-over-WireGuard).
- [ ] Tighten Hetzner firewall: consider restricting SSH/WireGuard inbound to known source
      IPs (weigh against CGNAT IP rotation).
- [ ] Fleet + Fleet Server setup → Elastic Agent enrollment → **Elastic Defend** integration
      (this is the next objective — the EDR telemetry path).

---

## Access quick-reference

```bash
# SSH to server
ssh -i ~/.ssh/id_ed25519_prismbox root@178.104.26.65

# Bring up WireGuard (host side) if not auto-started
sudo wg-quick up wg0
sudo wg show                      # look for "latest handshake"

# Elastic stack (on server)
cd /opt/prismbox/elastic
docker compose ps
docker compose logs -f kibana

# Kibana UI (host, tunnel up)
#   http://10.10.10.1:5601   — user: elastic
#   password: grep ELASTIC_PASSWORD /opt/prismbox/elastic/.env | cut -d'=' -f2
```
