# Magpie — Lumma Stealer Emulation

An 11-node kill chain emulating **Lumma Stealer** behaviour with **Atomic Red Team**, detonated on
`pb-victim-win10` against the PB-01 Elastic brain, then correlated node-by-node against ground truth.

- **Correlation phase: complete** — all 11 nodes reconstructed from independent evidence.
- **Rules phase: in progress** — see [`rules/`](#detection-rules-in-progress).

---

## Coverage matrix

**9 sole · 2 overlap. Defender caught 2 of 11 — both by command-line behavioural detection on the
delivery/transfer stages. Everything after the foothold passed the malware-NGAV tier untouched.**

| # | Technique | Test | Fired | Defender (1116/1117) | Coverage | Analysis |
|---|---|---|---|---|---|---|
| 00 | *driver* | detonation driver | — | — | — | [driver](./correlation/00-driver-execution/analysis.md) |
| 1 | T1204.002 | #12 ClickFix RunMRU → mshta | ✅ | none | **sole** | [01](./correlation/01-T1204.002/analysis.md) |
| 2 | T1218.005 | #10 Mshta exec PowerShell | ✅ | detect+act · `ClickFix.DJS!MTB` | overlap | [02](./correlation/02-T1218.005/analysis.md) |
| 3 | T1059.001 | #15 EncodedCommand param variations | ⚠️ harness | none | **sole** *(no artifact)* | [03](./correlation/03-T1059.001/analysis.md) |
| 4 | T1112 | #7 Set-ExecutionPolicy Bypass | ✅ | none | **sole** | [04](./correlation/04-T1112/analysis.md) |
| 5 | T1105 | #10 PowerShell Download | ✅ | detect+act · `Commandrob.A!ml` | overlap | [05](./correlation/05-T1105/analysis.md) |
| 6 | T1082 | #9 MachineGUID Discovery | ✅ | none | **sole** | [06](./correlation/06-T1082/analysis.md) |
| 7 | T1518.001 | #9 Defender Enumeration | ✅ *(exit 1)* | none | **sole** | [07](./correlation/07-T1518.001/analysis.md) |
| 8 | T1555.003 | #16 BrowserStealer | ✅ | none | **sole** | [08](./correlation/08-T1555.003/analysis.md) |
| 9 | T1539 | #4 Chrome v127+ cookies (remote debug) | ⚠️ failed | none | **sole** *(vs Chrome 151)* | [09](./correlation/09-T1539/analysis.md) |
| 10 | T1005 | #1 Stage files to zip | ✅ | none | **sole** | [10](./correlation/10-T1005/analysis.md) |
| 11 | T1041 | #1 C2 Data Exfiltration | ✅ | none | **sole** | [11](./correlation/11-T1041/analysis.md) |

`✅` fired and produced the technique's artifact · `⚠️` fired but the artifact was absent (node 03) or
the technique failed (node 09) — see those nodes for the distinction.

---

## The pinned chain (reproducibility)

Every node is pinned by **GUID**, verified against [`magpie-atomics-glossary.txt`](./magpie-atomics-glossary.txt)
and the run manifest. Technique ID says *what*; the GUID says *exactly which atomic*.

| # | Technique | Test | GUID |
|---|---|---|---|
| 1 | T1204.002 | #12 | `3f3120f0-7e50-4be2-88ae-54c61230cb9f` |
| 2 | T1218.005 | #10 | `8707a805-2b76-4f32-b1c0-14e558205772` |
| 3 | T1059.001 | #15 | `86a43bad-12e3-4e85-b97c-4d5cf25b95c3` |
| 4 | T1112 | #7 | `f3a6cceb-06c9-48e5-8df8-8867a6814245` |
| 5 | T1105 | #10 | `42dc4460-9aa6-45d3-b1a6-3955d34e1fe8` |
| 6 | T1082 | #9 | `224b4daf-db44-404e-b6b2-f4d1f0126ef8` |
| 7 | T1518.001 | #9 | `d3415a0e-66ef-429b-acf4-a768876954f6` |
| 8 | T1555.003 | #16 | `6f2c5c87-a4d5-4898-9bd1-47a55ecaf1dd` |
| 9 | T1539 | #4 | `b647f4ee-88de-40ac-9419-f17fac9489a7` |
| 10 | T1005 | #1 | `d3d9af44-b8ad-4375-8b0a-4bff4b7e419c` |
| 11 | T1041 | #1 | `d1253f6e-c29b-49dc-b466-2147a6191932` |

All 11 descend from a single driver process (`00-driver-execution/`) — one defined t-zero, one
traceable process tree, provably one controlled operation.

---

## Run 1 — the calibration run

Detonated with Windows Defender real-time protection **deliberately left on** — the realistic
condition for judging what custom rules add. Findings:

- Defender detected+remediated **2 of 11** nodes (02, 05), both via command-line behavioural
  detection, each a **1116 (detected) → 1117 (removed)** pair.
- The 2 blocked nodes still produced **full command-line telemetry in the 4688** — the process is
  created (and audited) before Defender's kill — so behavioural rule authoring loses nothing. No
  clean re-run was required.
- Mid-analysis the lab lost internet (unrelated), which forced correlation directly from raw Event
  Viewer alongside Kibana — a strength for the write-up, not a loss.

*Honesty note:* a pre-detonation VM snapshot was missed on this run (working-memory saturation during
simultaneous rework). Logged as a hard-gate checklist item; the run remained sufficient.

---

## Key findings

**The malware-NGAV tier stops at the foothold.** Both Defender hits are on delivery/transfer — mshta
proxying PowerShell (node 02) and a WebClient download (node 05). Discovery, credential access,
collection, and exfil were all undetected. That gap is the argument for behavioural detection
engineering on this platform.

**Defender interference triangulates from three independent artifacts.** Nodes 02 and 05 are each
marked, separately, by (1) the 1116/1117 pair, (2) a sparse Kibana process `end` document from the
remediation kill, and (3) blank `ProcessId`/`ExitCode` in the run manifest (the executor never got a
clean handle back). Reading any one alone can mislead; together they pin exactly which nodes Defender
touched — and confirm by exhaustion that no other node was affected.

**Process lifecycle: `start` vs `end`.** A killed process yields two coexisting EDR documents — a
rich `start` (full command line, ancestry) and a sparse `end` (termination, no identity). Nothing is
overwritten. Carry `event.action`/`event.type` when reading process events, or the sparse `end` reads
as "no data." Detection keys on the `start`; the immutable command line lives in the 4688 regardless.

**Exit code ≠ artifact fired (node 07).** The atomic exited 1, but the technique's artifact (the
Defender-enumeration command line) fired and was captured. Exit code is the atomic's self-report;
artifact-fired is whether the observable exists. Independent signals — check both.

**Harness ≠ technique (node 03).** The pinned process ran the AtomicTestHarnesses cmdlet, and its
`-Execute` produced **no** separate encoded-command child on either endpoint or SIEM telemetry. The
technique's own artifact never fired; only the harness is observable. Verified negatively on both
surfaces, recorded as a finding rather than assumed.

**Modern Chrome beat both browser-theft techniques (nodes 08 + 09).** The host was seeded with fake
credentials in Chrome only. Node 08's `BrowserCollector.exe` swept many browser profiles (Firefox
heaviest — the only one staged with readable test creds) but faces app-bound encryption on Chrome;
`file.path` proves *access*, not *extraction*. Node 09 targeted the correct Chrome Default profile via
remote debugging, but Chrome 151 blocks DevTools on the default profile (exit -1). Net: only the
staged Firefox data was actually collectable — the emulation shows Chrome's modern defences holding.

**The atomics are independent, not a wired data flow (node 11).** The exfil node generated its own
synthetic `LineNumbers.txt` and POSTed it to a placeholder domain — it did not send node 10's
`data.zip` or node 08's browser output. The chain shares the kill-chain *story*, not the actual
*data*. Accurate framing: *discrete TTPs emulated and each correlated*, not *loot exfiltrated
end-to-end*.

---

## Correlation methodology (reusable)

- **Three-artifact identity check:** CSV `ProcessId` = 4688 `New Process ID` (hex) = Kibana
  `process.entity_id`. Confirmed per node.
- **Ancestry:** every technique resolves through `process.parent.entity_id` to the executor shell and
  up to the driver root (`00-`).
- **Scaffolding vs technique:** `hostname.exe`/`whoami.exe` run before each atomic (executor
  bookkeeping) and `conhost.exe` after (OS console host). They are constant framework/OS noise —
  told apart from the technique by parent entity, never by timestamp proximity.
- **Facets share an entity:** one process fans out into `process` / `library` / `file` / `network` /
  `registry` / `dns` documents, all joined on `process.entity_id`; `event.category` selects the facet.
- **Sensor scope awareness:** registry *reads* (node 06 `REG QUERY`) are not logged by Defend, only
  *writes* (node 04 `Set-ExecutionPolicy`) are — so a missing registry event can be correct, not a
  gap. Drive the telemetry (e.g. add `file.path`) to answer scope questions the process tree alone
  can't.

---

## Detection rules (in progress)

> **Status: pending.** The correlation phase is complete; Sigma authoring is the next phase and lives
> in [`rules/`](./rules/), mirrored into the *the-forge* detection-as-code pipeline. Rules are
> written from the findings above and target the **sole-coverage** nodes first (net-new coverage over
> the malware-NGAV tier). Two nodes carry caveats the rule work must respect:
> - **Node 03** produced no encoded-command artifact this run — a T1059.001 EncodedCommand rule is
>   authored from the technique signature and validated later against a targeted atomic, not anchored
>   on the harness.
> - **Nodes 09/11** fired without succeeding / without sending real loot — rules target the *attempt*
>   (remote-debugging launch, POST exfil), which is fully observable regardless of outcome.

---

## Layout

```
magpie/
├── README.md                       # this file
├── magpie-atomics-glossary.txt     # GUID-pinned chain
├── correlation/                    # COMPLETE
│   ├── magpie-run1.csv             # run manifest (ground truth)
│   ├── 00-driver-execution/analysis.md
│   ├── 01-T1204.002/analysis.md
│   │   … 11-T1041/analysis.md
│   └── (screenshots per node folder)
└── rules/                          # IN PROGRESS
```
