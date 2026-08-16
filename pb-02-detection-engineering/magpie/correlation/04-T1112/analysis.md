# T1112 — Modify Registry

**Atomic test:** #7 — Change PowerShell Execution Policy to Bypass
**GUID:** `f3a6cceb-06c9-48e5-8df8-8867a6814245`
**Magpie chain position:** 4 of 11 · **Tactic:** Defense Evasion

> **MITRE technique** ("Modify Registry") vs. **atomic test** ("Change PowerShell Execution Policy to
> Bypass") — `Set-ExecutionPolicy -Scope LocalMachine` writes the ExecutionPolicy value into HKLM,
> **persisting** an execution-policy bypass in the registry. This is distinct from the driver's
> transient, process-scoped `-ExecutionPolicy Bypass` command-line flag (see `00-`): node 04 makes
> the bypass machine-wide and registry-backed.

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:11:26Z | 2026-08-14 20:11:26 | T1112 | #7 Change PowerShell Execution Policy to Bypass | 21968 | 0 |

The atomic runs `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine`, persisting a
machine-wide execution-policy bypass. `LocalMachine` scope writes to HKLM and therefore requires
elevation (consistent with the High integrity label below). Exit code 0 = success. Unlike node 03,
the technique's own artifact fired cleanly and is captured with its full command line.

---

## 2. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:11:27
- **New process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (New Process ID `0x55d0` = **21968**)
- **Process command line:** `"powershell.exe" & {Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine}`
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell, same parent as node 03)
- **Token Elevation Type:** `%%1937` (Type 2 — Full/elevated token)
- **Mandatory Label:** High Mandatory Level (LocalMachine scope requires elevation — consistent)
- **Account:** `DESKTOP-EB94L4C\pb-victim` (Logon ID `0x2B332E`)
- **Screenshot:** `01-security-4688.png`

**Identity cross-check (three artifacts agree):** CSV `ProcessId 21968` = 4688 `New Process ID
0x55d0` = Kibana `process.entity_id H/eDxx7b07dJ1gRa4e7qDw`. The 4688 is the immutable creation
record — the full `Set-ExecutionPolicy Bypass` command line is durably captured here.

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`, `event.category: process`**
- **@timestamp (UTC):** 2026-08-14 18:11:27.003Z (20:11:27.003 local — Discover renders browser-local CEST)
- **process.command_line:** `"powershell.exe" & {Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine}` (matches the 4688)
- **process.pe.original_file_name:** PowerShell.EXE · **code_signature.trusted:** true (Microsoft-signed binary)
- **process.entity_id:** `H/eDxx7b07dJ1gRa4e7qDw` (this node)
- **process.parent.entity_id:** `7/uSmidEJs8WDF8jpbJyvg` → the executor shell → resolves up to the driver root (see `00-`)
- **Screenshot:** `02-kibana-discover.png`

**Child (entity `H/eDxx7b07dJ`):** `conhost.exe` @ 20:11:27.018 — console host auto-attached by
Windows. Benign.

**Siblings (shared parent `DF8jpbJyvg`):** `hostname.exe` @ 20:11:25.837 (entity
`HYIVZZ5CeNZScWsIYnOxkQ`) and `whoami.exe` @ 20:11:25.872 — children of the *executor shell*, the
same parent as this node, not children of it. AtomicTestHarnesses scaffolding, not technique.

**Registry facet (T1112's direct artifact):** the process event above is the *actor* (powershell
executing `Set-ExecutionPolicy`); the technique's defining effect is the registry write to the HKLM
PowerShell ExecutionPolicy value, which lands under `event.category: registry` (with the
`registry.path`). It is not among the two process-focused screenshots here — confirm with a registry
filter on entity `H/eDxx7b07dJ` if the `registry.path` is needed for the record.

**Boundary marker:** the trailing rows at 20:11:05.x (`file` @ .444, `library` @ .080) carry entity
`j2ywQNnWjUVA` — node 03's harness doing its own late file/library activity, not node 04.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:11:26Z | UTC |
| CSV (Local) / Windows 4688 | 20:11:27 | CEST (UTC+2) |
| Kibana @timestamp (stored) | 18:11:27.003Z | UTC |
| Kibana Discover (displayed) | 20:11:27.003 | CEST (browser-local) |

Windows/local and Elastic/UTC differ by +2h — same event, reconciled. (The 1s CSV-vs-4688 offset is
the atomic firing → process logging gap, as in node 01.)

---

## 5. Verdict

- **Fired** (4688 present): **yes** — `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine` at 20:11:27, PID 21968
- **Defender AV detected** (1116): **no** — verified: node 04 (20:11:27) falls inside the
  Defender-silent gap between node 02's remediation (1117 @ 20:11:03) and node 05's detection
  (1116 @ 20:11:49). Confirmed by exhaustion: the full run holds exactly two 1116/1117 pairs
  (nodes 02 · ClickFix.DJS!MTB and 05 · Commandrob.A!ml), both attributed — none is left for this
  node to own.
- **Defender AV acted** (1117): **no**
- **Custom rule needed:** **yes — net-new coverage (sole coverage).** Defender was silent across the
  window; the execution-policy modification passed undetected.

**One-line summary:** PowerShell execution policy set to Bypass at LocalMachine scope — a persistent,
registry-backed policy modification — captured in endpoint telemetry (process + full command line)
with **no Defender AV detection**.

---

## Note — Defender gap placement

The two Defender detection/response pairs (node 02 @ 20:10:42 → 20:11:03, node 05 @ 20:11:49 →
20:12:05) are the only 1116/1117 events in the run. Node 04 (20:11:27) sits between them, in the
silent gap. Its sole-coverage status is placed by the gap **and confirmed by the actual start
timestamp** (20:11:27 < 20:11:49), not by kill-chain ordering alone.
