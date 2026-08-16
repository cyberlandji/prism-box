# PB-02 — Adversary Emulation & Detection Engineering

Second lab in the **Prism Box** series. Where PB-01 stood up the Elastic brain and enrolled the
victim endpoint, PB-02 uses that platform to **detonate real adversary techniques, correlate the
resulting telemetry against ground truth, and turn the findings into detection logic.**

The work is deliberately split into two phases per campaign:

1. **Correlation** — detonate a pinned technique chain, then reconstruct what actually happened from
   independent evidence sources (Windows Security 4688, Windows Defender Operational, Elastic Defend
   in Kibana) and a run manifest. Each technique gets its own `analysis.md`.
2. **Rules** — author and validate detection logic (Sigma) from what the correlation surfaced.
   Kept in a separate folder from correlation on purpose: *analysis* and *detection engineering* are
   two different skills with two different homes.

The first campaign, **Magpie** (Lumma Stealer emulation), has its correlation phase **complete** —
all 11 nodes analysed. This is what the current push contains.

---

## Environment

| Component | Detail |
|---|---|
| Victim | `pb-victim-win10` (`DESKTOP-EB94L4C`, `10.10.10.3`) — Windows 10, Elastic Defend enrolled |
| SIEM / brain | `prismbox-pb01` (`10.10.10.1`, Hetzner) — single-node Elastic 9.x via docker-compose, Fleet Server |
| Transport | all services bound to a WireGuard mesh |
| Operator | local Linux host (Invoke-AtomicTest driver, analysis) |

**Elastic Defend licence scope (load-bearing for the whole lab):** on the current non-Platinum
licence, only *Malware protection* is configurable — the behavioural protection suite is
Platinum-gated and inactive. Elastic Defend therefore runs as **telemetry + malware NGAV only**.
Every custom detection authored here is framed as **net-new coverage over that NGAV tier**, not as a
replacement for a behavioural engine that isn't running.

---

## Methodology

**GUID pinning for reproducibility.** Each node in a campaign is pinned by its Atomic Red Team
**GUID**, not by technique ID or test index. Technique ID says *what* (e.g. T1059.001), test index is
unstable across ART versions, and only the GUID identifies *exactly which* atomic ran. The pinned
GUIDs are recorded in the campaign glossary and verified against the run manifest — so the run is
reproducible rather than "some PowerShell test, roughly."

**Calibration run (Defender left on).** Magpie's Run 1 was detonated with Windows Defender real-time
protection deliberately **on**. That is the realistic condition — a defender assessing custom-rule
value wants to know what the AV tier already catches and what slips past. Nodes Defender blocked
still yielded full command-line telemetry in the 4688 (the process is created before the block), so
the run is sufficient for behavioural rule authoring; no clean re-run was needed. *(Honesty note: a
pre-detonation VM snapshot was missed on this run due to working-memory saturation during
simultaneous rework — logged as a hard-gate checklist item, not repeated.)*

**Three-artifact correlation.** Nothing rests on a single source. Every node is reconstructed from:
Windows Security **4688** (the immutable process-creation record — command line captured at birth,
unalterable by any later kill), **Elastic Defend** telemetry in Kibana (process / file / library /
network / registry / dns facets, joined on `process.entity_id`), and the **`magpie-run1.csv`** run
manifest. Identity is cross-checked across all three: CSV `ProcessId` = 4688 `New Process ID` (hex) =
Kibana `process.entity_id`.

**Time reconciliation (+2h).** Windows/victim logs in CEST (UTC+2); Elastic stores UTC. Kibana
Discover *displays* browser-local, which happens to be CEST here — so on screen the two line up, but
the stored `@timestamp` and the CSV UTC column carry the +2h. Every node states the reconciliation
explicitly.

**Honesty register.** Findings record what the telemetry proves, what it only indicates, and what it
cannot show — including techniques that *failed* and atomics that produced only harness scaffolding
rather than the technique's own artifact. Failures and null results are documented, not hidden.

---

## Magpie — Lumma Stealer emulation (correlation complete)

**11-node kill chain, one calibration run. Defender caught 2 of 11 — both by command-line
behavioural detection on the delivery/transfer stages; everything post-foothold (discovery,
credential access, collection, exfil) passed the NGAV tier untouched.**

| # | Technique | Test | Defender | Coverage |
|---|---|---|---|---|
| 1 | T1204.002 — User Execution | #12 ClickFix RunMRU → mshta | — | sole |
| 2 | T1218.005 — Mshta | #10 Mshta exec PowerShell | 1116/1117 · `ClickFix.DJS!MTB` | overlap |
| 3 | T1059.001 — PowerShell | #15 EncodedCommand param variations | — | sole *(harness only — no artifact)* |
| 4 | T1112 — Modify Registry | #7 Set-ExecutionPolicy Bypass | — | sole |
| 5 | T1105 — Ingress Tool Transfer | #10 PowerShell Download | 1116/1117 · `Commandrob.A!ml` | overlap |
| 6 | T1082 — System Info Discovery | #9 MachineGUID Discovery | — | sole |
| 7 | T1518.001 — Security Software Discovery | #9 Defender Enumeration | — | sole |
| 8 | T1555.003 — Credentials from Web Browsers | #16 BrowserStealer | — | sole |
| 9 | T1539 — Steal Web Session Cookie | #4 Chrome v127+ cookies (remote debug) | — | sole *(fired, failed vs Chrome 151)* |
| 10 | T1005 — Data from Local System | #1 Stage files to zip | — | sole |
| 11 | T1041 — Exfiltration Over C2 | #1 C2 Data Exfiltration | — | sole |

**Coverage: 9 sole · 2 overlap.** Full per-node evidence and the campaign methodology are in
[`magpie/README.md`](./magpie/README.md); each node's reconstruction is in
`magpie/correlation/NN-<technique>/analysis.md`.

Three run-level findings worth reading the detail for:
- **The NGAV tier stops at the foothold.** Both Defender hits landed on delivery/transfer (mshta
  ClickFix, WebClient download). Nothing after the foothold was detected — the concrete case for
  behavioural detection engineering.
- **Modern Chrome beat both browser-theft techniques.** Node 08's stealer hit app-bound encryption;
  node 09's remote-debugging attempt hit Default-profile DevTools hardening on Chrome 151 (exit -1).
  Only artificially-staged Firefox data was collectable.
- **The atomics are independent TTP demonstrations, not an end-to-end data flow.** The exfil node
  sent synthetic dummy data to a placeholder domain, not the collected loot. The accurate claim is
  *"the discrete TTPs Lumma uses were emulated and each one's telemetry correlated,"* not *"stolen
  credentials were exfiltrated end-to-end."*

---

## Roadmap (planned / in progress)

| Item | Status | Notes |
|---|---|---|
| Magpie — correlation | **complete** | all 11 nodes analysed (this push) |
| Magpie — detection rules | **in progress** | `rules/` stub present; Sigma authored from correlation findings, mirrored into *the-forge* |
| Brood — quiet-foothold campaign | **planned** | self-authored, single-host; kept separate from Magpie |
| Living-lab returns to PB-02 | **planned** | lateral movement, AD atomics, broader ATT&CK coverage — deferred, revisited iteratively |

PB-02 is treated as a living lab, not a one-shot deliverable — techniques are added over time rather
than exhaustively up front.

---

## Layout

```
pb-02-detection-engineering/
├── README.md                       # this file
└── magpie/
    ├── README.md                   # campaign overview + coverage matrix + findings
    ├── magpie-atomics-glossary.txt # GUID-pinned chain (reproducibility record)
    ├── correlation/                # COMPLETE
    │   ├── magpie-run1.csv         # run manifest (ground truth)
    │   ├── 00-driver-execution/    # operation t-zero + provenance root
    │   └── NN-<technique>/         # one folder per node, each with analysis.md
    └── rules/                      # IN PROGRESS — Sigma authored from correlation
```
