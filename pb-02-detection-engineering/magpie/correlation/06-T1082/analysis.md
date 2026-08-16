# T1082 — System Information Discovery

**Atomic test:** #9 — Windows MachineGUID Discovery
**GUID:** `224b4daf-db44-404e-b6b2-f4d1f0126ef8`
**Magpie chain position:** 6 of 11 · **Tactic:** Discovery

> **MITRE technique** ("System Information Discovery") vs. **atomic test** ("Windows MachineGUID
> Discovery") — `cmd.exe /c REG QUERY` reads the `HKLM\SOFTWARE\Microsoft\Cryptography` MachineGuid
> value, a stable per-install system identifier that loaders (Lumma included) use to fingerprint the
> host. This is a registry **read** (query), surfaced as a **two-process chain** (`cmd.exe` →
> `reg.exe`) — not a registry modification (contrast node 04).

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:12:11Z | 2026-08-14 20:12:11 | T1082 | #9 Windows MachineGUID Discovery | 11912 | 0 |

The atomic runs `cmd.exe /c REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v
MachineGuid`. Exit code 0 = success. The CSV `ProcessId` (11912 = `0x2e88`) is the **cmd.exe
wrapper** — the process the executor launched directly; `reg.exe` is cmd's child (§2). Both were
captured.

---

## 2. Endpoint evidence (Windows raw log)

The atomic is a two-process chain; both process-creation records were captured.

**Process 1 — `cmd.exe` (wrapper):**
- **Logged (local):** 20:12:11
- **New process:** `C:\Windows\System32\cmd.exe` (New Process ID `0x2e88` = **11912** = CSV ProcessId)
- **Process command line:** `"cmd.exe" /c REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid`
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell)
- **Token Elevation Type:** `%%1937` (Type 2 — Full/elevated) · **Mandatory Label:** High Mandatory Level
- **Screenshot:** `02-security-4688.png`

**Process 2 — `reg.exe` (query tool):**
- **Logged (local):** 20:12:11
- **New process:** `C:\Windows\System32\reg.exe` (New Process ID `0x2ae4` = **10980**)
- **Process command line:** `REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid`
- **Creator / parent process:** `C:\Windows\System32\cmd.exe` (Creator Process ID `0x2e88` = 11912 — the cmd wrapper above)
- **Token Elevation Type:** `%%1937` · **Mandatory Label:** High Mandatory Level
- **Screenshot:** `01-security-4688.png`

**Chain:** executor shell (powershell, 5180) → `cmd.exe` (11912) → `reg.exe` (10980). The
discriminating T1082 artifact — `REG QUERY …\Cryptography /v MachineGuid` — appears in both command
lines; `reg.exe` is the process that actually performs the read.

**Identity cross-check:** CSV `ProcessId 11912` = cmd 4688 `New Process ID 0x2e88` = Kibana entity
`/YV+7M+OSAJO…`. `reg.exe` = `0x2ae4` = Kibana entity `HO7uhw7uCQpX…`. The CSV records the
executor-launched process (cmd), not its child (reg).

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`, `event.category: process`**
- **`cmd.exe`** @ 20:12:11.399 — command_line `"cmd.exe" /c REG QUERY …\Cryptography /v MachineGuid`; entity `/YV+7M+OSAJOZI7zcqWRPQ`; parent.entity_id `7/uSmidEJs8WDF8jpbJyvg` (executor shell → driver root, see `00-`)
- **`conhost.exe`** @ 20:12:11.443 — entity `RyXaoF/PpVng40E6VQiNVg`; parent.entity_id `/YV+7M+OSAJO…` (cmd) — console host, benign
- **`reg.exe`** @ 20:12:11.519 — command_line `REG QUERY …\Cryptography /v MachineGuid`; entity `HO7uhw7uCQpXNdksfuHJ3Q`; parent.entity_id `/YV+7M+OSAJO…` (cmd) — the actual query
- **process.pe.original_file_name / code_signature.trusted:** reg.exe / Cmd.Exe, both `true` (signed Microsoft binaries; the *behaviour* is the signal)
- **Screenshots:** `03-kibana-discover.png`, `04-kibana-discover.png`

**Siblings (shared parent = executor shell `DF8jpbJyvg`):** `whoami.exe` @ 20:12:10.310 (entity
`ndVFOtoIy1QJ…`), with the hostname counterpart immediately prior — the standard scaffolding pair,
not technique.

**Registry facet — read, not write:** this atomic *queries* MachineGuid (`REG QUERY`); it does not
modify it. Elastic Defend logs registry create/set/delete, not reads, so — unlike node 04's
`Set-ExecutionPolicy` write — there is **no** `event.category: registry` document for this node, and
correctly so. The entire observable is the process chain and its command lines.

**System noise:** `smartscreen.exe` @ 20:12:22.929 (parent svchost) — benign, unrelated.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:12:11Z | UTC |
| CSV (Local) / Windows 4688 | 20:12:11 | CEST (UTC+2) |
| Kibana @timestamp — cmd (stored) | 18:12:11.399Z | UTC |
| Kibana @timestamp — reg (stored) | 18:12:11.519Z | UTC |
| Kibana Discover (displayed) | 20:12:11.x | CEST (browser-local) |

Windows/local and Elastic/UTC differ by +2h — same events, reconciled. The ~120 ms cmd→reg spacing
is the wrapper launching the query tool.

---

## 5. Verdict

- **Fired** (4688 present): **yes** — `cmd.exe` → `reg.exe` `REG QUERY MachineGuid` at 20:12:11 (cmd PID 11912, reg PID 10980)
- **Defender AV detected** (1116): **no** — verified: node 06 (20:12:11) falls after node 05's
  remediation (1117 @ 20:12:05) with no 1116 of its own. Confirmed by exhaustion: the full run holds
  exactly two 1116/1117 pairs (nodes 02 · ClickFix.DJS!MTB and 05 · Commandrob.A!ml), both
  attributed — none is left for this node to own.
- **Defender AV acted** (1117): **no**
- **Custom rule needed:** **yes — net-new coverage (sole coverage).** The MachineGUID discovery
  query passed undetected.

**One-line summary:** MachineGUID system-identifier discovery via `cmd.exe` → `reg.exe` `REG QUERY`
of `HKLM\…\Cryptography` — a registry read (no modification event) captured entirely as a
two-process chain, with **no Defender AV detection**.
