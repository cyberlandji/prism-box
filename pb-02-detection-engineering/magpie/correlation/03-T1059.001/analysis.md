# T1059.001 — Command and Scripting Interpreter: PowerShell

**Atomic test:** #15 — ATHPowerShellCommandLineParameter `-EncodedCommand` parameter variations
**GUID:** `86a43bad-12e3-4e85-b97c-4d5cf25b95c3`
**Magpie chain position:** 3 of 11 · **Tactic:** Execution

> **MITRE technique** ("Command and Scripting Interpreter: PowerShell") vs. **atomic test**
> ("ATHPowerShellCommandLineParameter — `-EncodedCommand` parameter variations"). The atomic uses
> the AtomicTestHarnesses cmdlet `Out-ATHPowerShellCommandLineParameter` to exercise the `-E`
> truncation of `-EncodedCommand`. On this run its `-Execute` produced **no separate
> `powershell -E <base64>` child** — the harness invocation is the only observable node 03 generated
> (see §5).

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:11:03Z | 2026-08-14 20:11:03 | T1059.001 | #15 `-EncodedCommand` param variations | 716 | 0 |

The atomic invokes `Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen
-EncodedCommandParamVariation E -Execute`. Exit code 0 = the harness reported success. The pinned
process (PID 716) is the harness itself; `-Execute` is designed to launch a `powershell -E <base64>`
child, but none was created on this run — confirmed against both endpoint and SIEM telemetry (§5).

---

## 2. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:11:03
- **New process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (New Process ID `0x2cc` = **716**)
- **Process command line:**
  `"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -Execute -ErrorAction Stop}`
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell)
- **Token Elevation Type:** `%%1937` (Type 2 — Full/elevated token)
- **Mandatory Label:** High Mandatory Level
- **Account:** `DESKTOP-EB94L4C\pb-victim` (Logon ID `0x2B332E`)
- **Screenshot:** `01-security-4688.png`

**Identity cross-check (three artifacts agree):** CSV `ProcessId 716` = 4688 `New Process ID 0x2cc`
= Kibana `process.entity_id j2ywQNnWjUVA`. The 4688 is the immutable creation record.

**No child process:** `0x2cc` appears in the Security log **only** as the New Process ID of the
harness — no 4688 carries `0x2cc` as its *Creator* Process ID. The harness spawned no audited child.

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`, `event.category: process`**
- **@timestamp (UTC):** 2026-08-14 18:11:03.823Z (20:11:03.823 local — Discover renders browser-local CEST)
- **process.command_line:** the `Out-ATHPowerShellCommandLineParameter … -Execute` harness invocation (matches the 4688)
- **process.pe.original_file_name:** PowerShell.EXE · **code_signature.trusted:** true (Microsoft-signed binary)
- **process.working_directory:** `C:\Users\PB-VIC~1\AppData\Local\Temp\…` (atomic temp dir)
- **process.entity_id:** `j2ywQNnWjUVAnuNahAaujA` (this node)
- **process.parent.entity_id:** `7/uSmidEJs8WDF8jpbJyvg` → the executor shell → resolves up to the driver root (see `00-`)
- **Screenshot:** `02-kibana-discover.png`

**Subtree confirmation (pivot on `process.parent.entity_id: j2ywQNnWjUVA`):** the harness's only
descendants are `conhost.exe` (console host, auto-attached) and its own `event.category: library`
DLL-load documents (@ 20:11:04.873–.892 — same `entity_id`, so the *same* process loading modules,
not new executions; `command_line` / `pe.original_file_name` `(null)` by design). After the library
loads, the next process events are node 04's `hostname.exe` / `whoami.exe`. No `powershell -E` child
appears between them.

**Siblings (shared parent `DF8jpbJyvg`):** the `hostname.exe` / `whoami.exe` pair adjacent to this
node are children of the *executor shell* — the same parent as node 03, not children of it. They are
AtomicTestHarnesses scaffolding (stamping host/user into the run result), not technique behaviour.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:11:03Z | UTC |
| CSV (Local) / Windows 4688 | 20:11:03 | CEST (UTC+2) |
| Kibana @timestamp (stored) | 18:11:03.823Z | UTC |
| Kibana Discover (displayed) | 20:11:03.823 | CEST (browser-local) |

Windows/local and Elastic/UTC differ by +2h — same event, reconciled. Display subtlety: Discover
renders browser-local (CEST), so on screen the 4688 (20:11:03) and Kibana (20:11:03.823) line up
directly; the +2h only appears against the stored UTC `@timestamp` and the CSV UTC column.

---

## 5. Finding — the observable is the harness; the encoded-command artifact never fired

**The observation.** The pinned process runs `Out-ATHPowerShellCommandLineParameter …
-EncodedCommandParamVariation E -Execute` — the AtomicTestHarnesses cmdlet, not a raw
`powershell -E <base64>`. `-Execute` is designed to launch the encoded invocation as a child, but a
full subtree check found none.

**The verification.**
- **Security 4688:** `0x2cc` (716) appears only as a *New* Process ID, never as a *Creator* — no audited child.
- **Kibana:** pivoting `process.parent.entity_id: j2ywQNnWjUVA` returns only `conhost` + the harness's own `library` loads; the next process events belong to node 04.

Both surfaces captured everything else in the run, so the absence is real, not a logging gap. The
technique's characteristic artifact — a `powershell.exe -EncodedCommand <base64>` process — never
appeared. Most likely the cmdlet validates the `-EncodedCommand` parameter *form* (or runs the
decoded payload inside its own runspace) rather than launching a distinct process for the
`E` / `-Execute` combination; confirming the exact mechanism would mean reading the
AtomicTestHarnesses source, but it does not change the correlation result.

**Attribution.** The adjacent `hostname` / `whoami` are scaffolding (parent = executor shell),
distinguished from any technique process by **ancestry + distinctive signature**, never by timestamp
proximity — the same discipline that corrected the node-02 ClickFix attribution.

**Generalises the node-02 lesson.** Node 02 showed one process → two lifecycle documents (`start` vs
`end`); node 03 shows one process → many documents across `event.category` (`process`, `library`)
sharing one `entity_id`. It adds a correlation check: **confirm the atomic actually produced the
technique's artifact before treating the node as complete.** Here it did not.

---

## 6. Verdict

- **Fired** (4688 present): **yes (harness only)** — `Out-ATHPowerShellCommandLineParameter` at 20:11:03, PID 716. The technique's own `powershell -EncodedCommand <base64>` artifact did **not** fire (§5).
- **Defender AV detected** (1116): **no** — verified: no 1116 between node 02's remediation
  (1117 @ 20:11:03) and node 05's detection (1116 @ 20:11:49). The 1117 @ 20:11:03 is Defender
  finishing the *Remove* of node 02's ClickFix detection (a same-second coincidence), not a reaction
  to this node. Confirmed by exhaustion: the full run holds exactly two 1116/1117 pairs (nodes 02 ·
  ClickFix.DJS!MTB and 05 · Commandrob.A!ml), both attributed — none is left for this node to own.
- **Defender AV acted** (1117): **no** (for this node)
- **Custom rule needed:** **sole coverage** — Defender was silent across the window. Coverage caveat:
  this run captured the harness only, not the encoded-command artifact (§5).

**One-line summary:** the atomic ran as an ATH parameter-parsing harness and produced **no genuine
encoded-command process** — no `powershell -E <base64>` child on either endpoint or SIEM telemetry.
The surviving observable is the harness invocation; Defender was silent across the window.

---

## Note — child-process check (closed)

The `-Execute` switch is designed to launch `powershell.exe -E <base64>`. Both surfaces were checked
and the child does **not** exist for this run:
- **Security 4688:** no event carries Creator Process ID `0x2cc` (716). Only the harness itself uses `0x2cc`, as its New Process ID.
- **Kibana:** `event.module: "endpoint" and process.parent.entity_id: "j2ywQNnWjUVAnuNahAaujA"` returns only `conhost` + the harness's own `library` documents; the next process events are node 04's `hostname`/`whoami`.

Recorded as the node's finding (§5), not a pending item.










