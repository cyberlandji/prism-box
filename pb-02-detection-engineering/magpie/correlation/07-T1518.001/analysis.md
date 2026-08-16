# T1518.001 — Software Discovery: Security Software Discovery

**Atomic test:** #9 — Security Software Discovery - Windows Defender Enumeration
**GUID:** `d3415a0e-66ef-429b-acf4-a768876954f6`
**Magpie chain position:** 7 of 11 · **Tactic:** Discovery

> **MITRE technique** ("Software Discovery: Security Software Discovery") vs. **atomic test**
> ("Windows Defender Enumeration") — a single powershell running `Get-Service WinDefend`,
> `Get-MpComputerStatus`, and `Get-MpThreat` to enumerate Defender's service state, protection
> configuration, and detected-threat history. Reconnaissance of the host's security tooling — a
> loader checking what it is up against. The atomic exits **1** (the only non-zero exit in the run so
> far); §5 separates the atomic's self-check from whether the technique artifact fired.

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:12:32Z | 2026-08-14 20:12:32 | T1518.001 | #9 Windows Defender Enumeration | 19240 | **1** |

A single powershell process runs three Defender-enumeration cmdlets. ExitCode 1 — the only non-zero
exit so far. The enumeration command line is captured regardless (§2); the exit code is the atomic's
self-report, a separate matter (§5).

---

## 2. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:12:32
- **New process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (New Process ID `0x4b28` = **19240** = CSV ProcessId)
- **Process command line:** `"powershell.exe" & {Get-Service WinDefend #check the service state of Windows Defender Get-MpComputerStatus #provides the current status of security solution elements, including Anti-Spyware, Antivirus, IoavProtection, Real-time protection, etc Get-MpThreat #threats details that have been detected using MS Defender}`
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell)
- **Token Elevation Type:** `%%1937` (Type 2 — Full/elevated) · **Mandatory Label:** High Mandatory Level
- **Screenshot:** `01-security-4688.png`

**Identity cross-check:** CSV `ProcessId 19240` = 4688 `New Process ID 0x4b28` = Kibana
`process.entity_id T40RDezeUjM6/RT/zmYdOA`.

The three enumeration cmdlets — `Get-Service WinDefend`, `Get-MpComputerStatus`, `Get-MpThreat` — are
the discriminating T1518.001 artifact, all present in the immutable command line.

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`, `event.category: process`**
- **`powershell.exe`** (node 07) @ 20:12:32.721 — command_line the three-cmdlet Defender enumeration; entity `T40RDezeUjM6/RT/zmYdOA`; parent.entity_id `7/uSmidEJs8WDF8jpbJyvg` (executor shell → driver root, see `00-`)
- **`conhost.exe`** @ 20:12:32.792 — entity `OlP3pIQmL+TtZ7xk87px7w`; parent.entity_id `T40RDezeUjM6…` (node 07) — console host, benign
- **`library`** @ 20:12:32.855 — entity `T40RDezeUjM6…` (the *same* powershell loading a DLL; command_line / pe.original_file_name `(null)` by design)
- **process.pe.original_file_name / code_signature.trusted:** PowerShell.EXE / `true` (signed Microsoft binary — the *behaviour* is the signal)
- **Screenshot:** `02-kibana-discover.png`

**Siblings (shared parent = executor shell `DF8jpbJyvg`):** `hostname.exe` @ 20:12:32.226 and
`whoami.exe` @ 20:12:32.272 — the standard scaffolding pair, not technique.

**No registry facet:** the technique uses service / CIM cmdlets (`Get-Service`,
`Get-MpComputerStatus`, `Get-MpThreat`), not the registry — the observable is the single process and
its command line.

**System noise:** `smartscreen.exe` @ 20:12:22.929 (parent svchost) — benign, unrelated.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:12:32Z | UTC |
| CSV (Local) / Windows 4688 | 20:12:32 | CEST (UTC+2) |
| Kibana @timestamp (stored) | 18:12:32.721Z | UTC |
| Kibana Discover (displayed) | 20:12:32.721 | CEST (browser-local) |

Windows/local and Elastic/UTC differ by +2h — same event, reconciled.

---

## 5. Finding — exit code ≠ artifact fired

The atomic exited **1**, but the technique artifact fired cleanly. These are two independent things:

- **Artifact fired** = the technique's observable exists. Here the 4688 captured the powershell with
  all three Defender-enumeration cmdlets in the command line — present, immutable, and the exact
  string a T1518.001 observable rests on.
- **Exit code** = the atomic's own self-report of success. Exit 1 means Invoke-AtomicTest's success
  check did not pass, for a reason not resolvable from process telemetry.

**What the telemetry cannot tell you.** The display collapses any newlines, and the cmdlets are
separated by `#` inline comments. From process telemetry alone you cannot tell whether all three
cmdlets executed or only the first — if the block ran as a single line, everything after the first
`#` is a comment. Determining that would need PowerShell ScriptBlock / module logging or a transcript,
which this telemetry does not include. For correlation this does not change the verdict: the
enumeration command line is captured in full.

**Contrast with node 03.** There the artifact never fired (only the harness). Here the artifact fired
and is fully captured; only the atomic's self-check failed. Check both signals; conflate neither.

---

## 6. Verdict

- **Fired** (4688 present): **yes** — Defender-enumeration powershell (`Get-Service WinDefend` /
  `Get-MpComputerStatus` / `Get-MpThreat`) at 20:12:32, PID 19240. (Atomic ExitCode 1 is a self-check
  outcome, not the artifact — §5.)
- **Defender AV detected** (1116): **no** — verified: node 07 (20:12:32) falls after node 05's
  remediation (1117 @ 20:12:05) with no 1116 of its own. Confirmed by exhaustion: the full run holds
  exactly two 1116/1117 pairs (nodes 02 · ClickFix.DJS!MTB and 05 · Commandrob.A!ml), both
  attributed — none is left for this node to own.
- **Defender AV acted** (1117): **no**
- **Custom rule needed:** **yes — net-new coverage (sole coverage).** The Defender enumeration passed
  undetected — Defender did not flag reconnaissance of itself at this tier.

**One-line summary:** Windows Defender security-software enumeration via a single powershell
(`Get-Service WinDefend` / `Get-MpComputerStatus` / `Get-MpThreat`), the artifact fully captured in
the immutable command line, with **no Defender AV detection**. The atomic's exit 1 is a self-check
outcome, distinct from the artifact firing (§5).
