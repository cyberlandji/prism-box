# Operation Prism Box

**A self-built, four-phase detection engineering lab — from a hardened Elastic SIEM foundation
to EDR telemetry, detection-as-code, automated response, and a Microsoft Sentinel mirror.**

Prism Box is a hands-on blue-team lab built on real cloud infrastructure (not a pre-packaged
"click to deploy" range). Every layer is provisioned, configured, secured, and validated by
hand — the goal is deep understanding of *how a detection stack actually works*, end to end,
rather than surface familiarity with a tool's UI.

It follows a three-layer working philosophy carried across the whole portfolio:
**Build** (architect the system) → **Configure** (engineer it correctly and securely) →
**Validate** (verify detections fire on real telemetry).

---

## Architecture

A single Elasticsearch "brain" runs on a hardened cloud VM. A Windows endpoint on separate
physical hardware ships EDR telemetry to it. All administrative access runs over a private
WireGuard tunnel — the SIEM is never exposed to the public internet.

```
┌─────────────────────────┐         WireGuard tunnel          ┌──────────────────────────┐
│   Host (analyst)         │◄─────── 10.10.10.0/24 ──────────►│  Hetzner CX33 (Nürnberg) │
│   Kibana over tunnel     │                                   │  Elasticsearch + Kibana  │
└─────────────────────────┘                                   │  (single-node, TLS, auth)│
                                                               └────────────▲─────────────┘
                                                                            │ Elastic Agent
                                                                            │ (outbound)
                                                              ┌─────────────┴─────────────┐
                                                              │  Windows endpoint         │
                                                              │  Elastic Defend (EDR)     │
                                                              └───────────────────────────┘
```

---

## Phases

| Phase | Focus | Status |
|-------|-------|--------|
| **PB-01 — Elastic Foundation** | Hardened single-node Elasticsearch + Kibana on cloud infra, WireGuard admin tunnel, Elastic Defend EDR groundwork. | 🟢 Foundation standing |
| **PB-02 — Detection Engineering** | Atomic Red Team on the endpoint; authoring and validating detection rules against real telemetry. | ⚪ Planned |
| **PB-03 — Automated Response** | Hardening pass + SOAR automation (Shuffle) for response workflows. | ⚪ Planned |
| **PB-04 — Sentinel Mirror** | Microsoft-stack mirror: Defender for Endpoint + Sentinel, KQL translation of the detection logic. | ⚪ Planned |

---

## Tech stack

- **Infrastructure:** Hetzner Cloud (CX33, Ubuntu 24.04 LTS)
- **SIEM:** Elasticsearch + Kibana 9.x (single-node, security + TLS enabled)
- **EDR:** Elastic Agent + Elastic Defend integration (via Fleet)
- **Networking:** WireGuard (private admin mesh), Hetzner Cloud Firewall
- **Containerization:** Docker Engine + Compose
- **Adversary emulation:** Atomic Red Team *(PB-02)*
- **SOAR:** Shuffle *(PB-03)*
- **Cloud-native mirror:** Microsoft Defender for Endpoint + Sentinel *(PB-04)*

---

## Design principles

- **Secure by default.** The SIEM binds only to the WireGuard interface — zero public exposure.
  TLS and authentication are enabled from the first boot, not bolted on later.
- **Infrastructure and config as the source of truth.** Compose files, tunables, and firewall
  rules are version-controlled; secrets are never committed (see `.gitignore` / `.env.example`).
- **Build with friction, on purpose.** Each layer is done by hand so the failure modes are
  understood, not abstracted away. Troubleshooting is documented, not hidden.

---

## Repository structure

```
prism-box/
├── pb-01-elastic-foundation/     # SIEM foundation, WireGuard, EDR groundwork
│   ├── docker-compose.yml        # Elastic stack (secrets gitignored)
│   ├── .env.example              # config template (no secrets)
│   └── docs/
│       └── session-log.md        # build + troubleshooting record
├── pb-02-detection-engineering/
├── pb-03-automated-response/
└── pb-04-sentinel-mirror/
```

---

*Part of a broader detection-engineering portfolio. See also **The Forge** (detection-as-code
CI pipeline) and the **PCAP Autopsy** series (behavioural Suricata rule development).*
