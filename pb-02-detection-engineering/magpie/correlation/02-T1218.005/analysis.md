# T1218.005 — System Binary Proxy Execution: Mshta

**Atomic test:** #10 — Mshta used to Execute PowerShell
**GUID:** `8707a805-2b76-4f32-b1c0-14e558205772`
**Magpie chain position:** 2 of 11 · **Tactic:** Defense Evasion / Execution

> **MITRE technique** ("System Binary Proxy Execution: Mshta") vs. **atomic test** ("Mshta used to
> Execute PowerShell") — abusing the signed, trusted `mshta.exe` LOLBin to proxy execution of an
> inline HTA that spawns PowerShell, evading naive process-name allowlists.

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test |
|----------------------|------------------------|-----------|------|
| 2026-08-14T18:10:41Z | 2026-08-14 20:10:41 | T1218.005 | #10 Mshta used to Execute PowerShell |

`cmd.exe` launches `mshta.exe` with an inline `about:` HTA containing VBScript that calls
`Wscript.Shell.Run` to execute `powershell.exe`. This is the execution stage that follows the
node 01 ClickFix delivery.

---

## 2. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:10:41
- **New process:** `C:\Windows\System32\cmd.exe`
- **Process command line:**
  `"cmd.exe" /c mshta.exe about:<hta:application><script language="VBScript">Close(Execute("CreateObject(""Wscript.Shell"").Run(""powershell.exe -nop -Command Write-Host Hello, MSHTA!;Start-Sleep -Seconds 5"")"))</script>`
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (the driver)
- **Mandatory Label:** High Mandatory Level
- **Creator Subject:** `DESKTOP-EB94L4C\pb-victim`
- **Screenshot:** `01-security-4688.png`

The full mshta → PowerShell command chain is captured here at process creation. **This 4688 is the
durable record of what executed** (see §6 — the EDR view is reshaped by remediation; the 4688 is not).

---

## 3. Defender evidence (detection + response)

**Defender Operational — Event 1116 (detected):**
- **Logged (local):** 20:10:42
- **Threat:** `Trojan:Win32/ClickFix.DJS!MTB` — Severity: Severe — Category: Trojan
- **Detection Type:** Concrete · **Detection Source:** System
- **Path:** `CmdLine:_C:\Windows\System32\cmd.exe /c mshta.exe about:<hta...>` — i.e. the detection
  matched on **node 02's command line**, confirming this ClickFix-named detection belongs to
  T1218.005, not to node 01's RunMRU write.
- **Screenshot:** `02-defender-1116.png`

**Defender Operational — Event 1117 (action taken):**
- **Logged (local):** 20:11:03
- **Action:** Remove — Action Status: "No additional actions required" — Error: 0x0 (success)
- **Screenshot:** `03-defender-1117.png`

**Detect → act pattern:** 1116 (20:10:42) → 1117 (20:11:03), a ~21s gap. Every 1117 follows a
1116 (detection causes remediation); there is no 1117 without a preceding 1116.

---

## 4. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`, `event.category: process`**
- The process-creation (`start`) event carries the full mshta command line and ancestry
  (`process.parent.entity_id` → driver root, see `00-`).
- A second, **sparse `end` event** appears at **20:10:42.037** — see §6.
- **@timestamp (UTC):** 18:10:41Z (start) / 18:10:42Z (end)
- **Screenshots:** `04-kibana-discover.png`, `05-kibana-event-action.png`

---

## 5. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:10:41Z | UTC |
| Windows 4688 (start) | 20:10:41 | CEST (UTC+2) |
| Defender 1116 (detect) | 20:10:42 | CEST |
| Defender 1117 (remove) | 20:11:03 | CEST |
| Kibana `end` event | 18:10:42Z | UTC |

Windows/local and Elastic/UTC differ by +2h — reconciled.

---

## 6. Finding — process-lifecycle telemetry: `start` vs `end`

**The observation.** In Kibana, a process event at 20:10:42 appeared with *blank identity* —
`process.name (blank)`, `pe.original_file_name (null)`, `command_line (blank)`, and parent
`System Idle Process`. At first glance this looks like an empty/broken record.

**The concern.** The process was killed ~22s after creation (created 20:10:41, detected 20:10:42,
removed by Defender 20:11:03). Did Defender's remediation *alter* the live telemetry — could what
was observable at runtime be changed after the fact?

**The verification.** Adding `event.action` / `event.type` as columns resolved it:
- Normal process rows show `event.action: [start, end]` — a full lifecycle with identity.
- The blank row shows **`event.action: end` and `event.type: end` only** — it is a process
  **termination event**, not a hollow `start`.

**The conclusion.** The mshta process produced **two separate lifecycle documents**:
1. a **`start`** at creation — carrying the full command line, identity, and ancestry;
2. an **`end`** at Defender's removal — sparse by design, marking termination, not identity.

Nothing was overwritten or altered. The `start` persists unchanged; a separate, sparse `end`
document was *added* when the process died. The confusion arose only from reading process events
without distinguishing `start` from `end`.

**Why it matters:**
- **Read the lifecycle, not just the event.** Always carry `event.action` when reading process
  telemetry — without it, `start` and `end` are indistinguishable and the sparse `end` reads as
  "no data." An analyst filtering process events post-remediation can encounter the hollow `end`
  and wrongly conclude nothing meaningful ran.
- **The immutable audit record is the 4688.** Windows Security 4688 is written once at creation
  and cannot be reached by later remediation — the full mshta command line is durably there. EDR
  gives *both* `start` and `end` as coexisting documents; the `start` holds the evidence.
- **Detection rules key on the `start`.** A Sigma rule for this node targets the process-creation
  event (`event.action: start`) where the command line exists — never the sparse `end`.

---

## 7. Verdict

- **Fired** (4688 present): **yes** — cmd → mshta → PowerShell at 20:10:41
- **Defender AV detected** (1116): **yes** — `Trojan:Win32/ClickFix.DJS!MTB`, Concrete, at 20:10:42
- **Defender AV acted** (1117): **yes** — Remove, at 20:11:03
- **Custom rule needed:** **overlap** — Defender AV already detects and removes this node. A custom
  rule adds defense-in-depth and must key on the **process-creation (`start`) command line**
  (mshta spawning PowerShell), because the EDR `end` record is blank and the 4688 is the durable
  source.

**One-line summary:** mshta-proxied PowerShell execution — detected and removed by Defender AV via
command-line behavioral detection. Notable finding: Defender's remediation produced a sparse EDR
`end` event; the durable evidence (full command line) lives in the process-creation `start` /
Windows 4688, which detection rules must target.
