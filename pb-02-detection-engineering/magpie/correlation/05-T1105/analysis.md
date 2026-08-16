# T1105 — Ingress Tool Transfer

**Atomic test:** #10 — Windows - PowerShell Download
**GUID:** `42dc4460-9aa6-45d3-b1a6-3955d34e1fe8`
**Magpie chain position:** 5 of 11 · **Tactic:** Command and Control

> **MITRE technique** ("Ingress Tool Transfer") vs. **atomic test** ("Windows - PowerShell
> Download") — `(New-Object System.Net.WebClient).DownloadFile(...)` pulls a remote file to disk,
> emulating a loader fetching its next stage. The atomic downloads the atomic-red-team `LICENSE.txt`
> as a benign stand-in. This is the **second Defender-blocked node** — command-line behavioural
> detection as `Trojan:Win32/Commandrob.A!ml`.

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:11:48Z | 2026-08-14 20:11:48 | T1105 | #10 Windows - PowerShell Download | *(blank)* | *(blank)* |

The atomic runs `(New-Object System.Net.WebClient).DownloadFile("…/LICENSE.txt",
"$env:TEMP\Atomic-license.txt")`, fetching a remote file to the temp directory.

**Note the blanks:** `ProcessId` and `ExitCode` are empty in the CSV. The only other blank-ProcessId
row in the whole run is node 02 (T1218.005) — the other Defender-blocked node. The atomic executor
records a clean ProcessId/ExitCode for the 9 nodes that ran to completion, but not for the 2 Defender
removed. This is an independent, third signal of Defender interference (§6).

---

## 2. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:11:49
- **New process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (New Process ID `0x4e90` = **20112**)
- **Process command line:** `"powershell.exe" & {(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt", "$env:TEMP\Atomic-license.txt")}`
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell, same parent as nodes 03 & 04)
- **Token Elevation Type:** `%%1937` (Type 2 — Full/elevated token)
- **Mandatory Label:** High Mandatory Level
- **Account:** `DESKTOP-EB94L4C\pb-victim` (Logon ID `0x2B332E`)
- **Screenshot:** `01-security-4688.png`

The 4688 is written at process creation — **before** Defender's detection (20:11:49) and removal
(20:12:05). The full DownloadFile command line is durably captured here and cannot be altered by the
later kill (same principle as node 02). Because the CSV ProcessId is blank, the 4688 `New Process ID
0x4e90` is the authoritative process identity for this node.

---

## 3. Defender evidence (detection + response)

**Defender Operational — Event 1116 (detected):**
- **Logged (local):** 20:11:49
- **Threat:** `Trojan:Win32/Commandrob.A!ml` — ID 2147849223 — Severity: Severe — Category: Trojan
- **Detection Type:** FastPath · **Detection Source:** System · **Detection Origin:** Unknown
- **Path:** `CmdLine:_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe & {(New-Object System.Net.WebClient).DownloadFile("…/LICENSE.txt", "$env:TEMP\Atomic-license.txt")}` — the detection matched on **node 05's command line** (the DownloadFile), confirming this `Commandrob` detection belongs to T1105.
- **User:** NT AUTHORITY\SYSTEM · **Process Name:** Unknown
- **Screenshot:** `02-defender-1116.png`

**Defender Operational — Event 1117 (action taken):**
- **Logged (local):** 20:12:05
- **Action:** Remove — Action Status: "No additional actions required" — Error Code: 0x0 (success)
- **Threat:** same — `Trojan:Win32/Commandrob.A!ml`, ID 2147849223
- **Screenshot:** `03-defender-1117.png`

**Detect → act pattern:** 1116 (20:11:49) → 1117 (20:12:05), a ~16s gap. Consistent with the run's
pairing rule — every 1117 follows a 1116; no 1117 without a preceding 1116. This is the **second and
final** detect/act pair in the run (the first belongs to node 02).

---

## 4. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`, columns include `event.category` / `event.action` /
`event.type`**
- The process-creation (`start`) event carries the full DownloadFile command line and ancestry
  (parent → executor shell → driver root, see `00-`).
- A **sparse `end` event** appears at **20:11:49.394** — `event.action: end`, `event.type: end`,
  blank name / command_line, parent `System Idle Process` — the process **termination** from
  Defender's Remove (see §6).
- **@timestamp (UTC):** 18:11:49.394Z (20:11:49.394 local) for the `end` event.
- **Screenshot:** `04-kibana-discover.png`

**Siblings (shared parent = executor shell):** `hostname.exe` @ 20:11:47.833 (entity
`PL6eiDbm0sTO`) and `whoami.exe` @ 20:11:47.870 (entity `AWzUEbf7V9xR`) — scaffolding, both showing
`[start, end]`.

**System noise (Defender activity):** `MsMpEng.exe` `network / disconnect_received` @ 20:11:49.116,
and `SecurityHealthHost.exe` @ 20:11:49.438 — benign, spawned around Defender's action.

**Boundary marker:** the `file` `overwrite` / `change` event carrying entity `H/eDxx7b07dJ` is node
04's Set-ExecutionPolicy process (late file activity), not node 05.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 5. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:11:48Z | UTC |
| Windows 4688 (start) | 20:11:49 | CEST (UTC+2) |
| Defender 1116 (detect) | 20:11:49 | CEST |
| Defender 1117 (remove) | 20:12:05 | CEST |
| Kibana `end` event (stored) | 18:11:49.394Z | UTC |

Windows/local and Elastic/UTC differ by +2h — same event, reconciled.

---

## 6. Finding — lifecycle pattern confirmed (n=2), and three artifacts converge

**The lifecycle pattern repeats.** Node 05 reproduces node 02's `start` vs `end` telemetry exactly:
a rich `start` (full DownloadFile command line, ancestry) and a separate **sparse `end`** (blank
identity, parent `System Idle Process`) added at Defender's kill. Nothing is overwritten — a
termination document is *added* alongside the immutable `start`. This is the **second** Defender-
blocked node to show the identical signature, which confirms node 02's finding is a general property
of Defender remediation in this telemetry, not a one-off.

**Three independent artifacts converge on the same two nodes.** The Defender-interfered nodes (02 and
05) are marked, separately, by:
1. the **1116/1117** detect/act pairs (Defender's own record);
2. the **sparse Kibana `end`** events (EDR termination signature);
3. the **blank CSV `ProcessId` / `ExitCode`** (the atomic executor never got a clean handle back).

Any one read in isolation could mislead — the blank `end` looks like "no data," a blank CSV cell
looks like a logging miss. Together they triangulate exactly which nodes Defender removed.

**Correlation lessons.** Carry `event.action` / `event.type` when reading process events, or `start`
and `end` are indistinguishable and the sparse `end` reads as empty. The Windows 4688 is the
immutable creation record — the command line lives there regardless of the later kill. And the CSV's
`ProcessId` / `ExitCode` columns are a cheap, run-wide tell for Defender interference.

---

## 7. Verdict

- **Fired** (4688 present): **yes** — powershell `WebClient.DownloadFile` at 20:11:49, New Process ID `0x4e90`
- **Defender AV detected** (1116): **yes** — `Trojan:Win32/Commandrob.A!ml`, FastPath, at 20:11:49
- **Defender AV acted** (1117): **yes** — Remove, at 20:12:05
- **Custom rule needed:** **overlap** — Defender AV already detects and removes this node. Durable
  evidence for any custom coverage is the process-creation `start` command line, not the sparse
  `end` (§6).

**One-line summary:** a `WebClient.DownloadFile` ingress transfer — detected and removed by Defender
AV via command-line behavioural detection (`Commandrob.A!ml`). Reproduces node 02's `start` vs `end`
lifecycle (sparse `end` from remediation), and the CSV's blank `ProcessId` / `ExitCode`
independently marks it — with node 02 — as Defender-interfered. The durable command-line evidence
lives in the process-creation `start` / Windows 4688.
