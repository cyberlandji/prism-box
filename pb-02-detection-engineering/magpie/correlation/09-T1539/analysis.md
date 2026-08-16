# T1539 — Steal Web Session Cookie

**Atomic test:** #4 — Steal Chrome v127+ cookies via Remote Debugging (Windows)
**GUID:** `b647f4ee-88de-40ac-9419-f17fac9489a7`
**Magpie chain position:** 9 of 11 · **Tactic:** Credential Access

> **MITRE technique** ("Steal Web Session Cookie") vs. **atomic test** ("Steal Chrome v127+ cookies
> via Remote Debugging") — a powershell script relaunches Chrome with `--remote-debugging-port`, then
> drives the Chrome DevTools Protocol (CDP) `Network.getAllCookies` over a websocket to dump the
> session cookies. This is the Chrome counterpart to node 08's browser theft. On this host the target
> is **Chrome 151** and the atomic exits **-1** — the technique fired but did not succeed (§5).

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:13:19Z | 2026-08-14 20:13:19 | T1539 | #4 Steal Chrome v127+ cookies via Remote Debugging | 24416 | **-1** |

A powershell script kills any running Chrome, relaunches it with `--remote-debugging-port=9222
--profile-directory=Default`, waits, then connects to the DevTools websocket and issues
`Network.getAllCookies`. ExitCode -1 = a terminating error; the atomic did not complete cleanly (§5).
The CSV `ProcessId` (24416) is the script's powershell.

---

## 2. Endpoint evidence (Windows raw log)

**Process 1 — `powershell.exe` (the CDP cookie-theft script):**
- **Logged (local):** 20:13:21
- **New process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (New Process ID `0x5f60` = **24416** = CSV ProcessId)
- **Process command line (abridged):**
  ```
  "powershell.exe" & {$devToolsPort = 9222
  $testUrl = "https://www.google.com/"
  stop-process -name "chrome" -force -erroraction silentlycontinue
  $chromeProcess = Start-Process "chrome.exe" "$testUrl --remote-debugging-port=$devToolsPort --profile-directory=Default" -PassThru
  Start-Sleep 10
  $jsonResponse = Invoke-WebRequest "http://localhost:$devToolsPort/json" -UseBasicParsing
  $devToolsPages = ConvertFrom-Json $jsonResponse.Content
  $ws_url = $devToolsPages[0].webSocketDebuggerUrl
  $ws = New-Object System.Net.WebSockets.ClientWebSocket
  ... $ws.ConnectAsync(...) ...
  $GET_ALL_COOKIES_REQUEST = '{"id": 1, "method": "Network.getAllCookies"}'
  ... $ws.SendAsync(...) ... receive loop ...
  try { $response = ConvertFrom-Json $completeMessage.ToString(); $cookies = $response.result.cookies }
  catch { Write-Host "Error parsing JSON data." }
  Write-Host $cookies
  Stop-Process $chromeProcess -Force}
  ```
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell)
- **Token Elevation Type:** `%%1937` · **Mandatory Label:** High Mandatory Level
- **Screenshots:** `01-security-4688_1.png`, `01-security-4688_2.png`

**Process 2 — `chrome.exe` (remote-debugging launch):**
- **Logged (local):** 20:13:22
- **New process:** `C:\Program Files\Google\Chrome\Application\chrome.exe` (New Process ID `0x59e4` = **23012**)
- **Process command line:** `"C:\Program Files\Google\Chrome\Application\chrome.exe" https://www.google.com --remote-debugging-port=9222 --profile-directory=Default`
- **Creator / parent process:** `powershell.exe` (Creator Process ID `0x5f60` = 24416 — the script above)
- **Screenshot:** `02-security-4688.png`

**Process 3 — `chrome.exe` (crashpad-handler child — carries the version):**
- **Logged (local):** 20:13:22
- **New process:** `C:\Program Files\Google\Chrome\Application\chrome.exe` (New Process ID `0x4f94` = **20372**)
- **Process command line:** `"…chrome.exe" --type=crashpad-handler "--user-data-dir=C:\Users\pb-victim\AppData\Local\Google\Chrome\User Data" … --annotation=prod=Chrome --annotation=ver=151.0.7922.138 …`
- **Creator / parent process:** `chrome.exe` (Creator Process ID `0x59e4` = 23012 — chrome main)
- **Screenshot:** `03-security-4688.png`

**Chain:** executor shell (5180) → powershell (24416) → `chrome.exe` main (23012) →
`chrome.exe` crashpad + renderers/gpu/utility (20372, …). **Chrome version = 151.0.7922.138**, far
past v127.

**Identity cross-check:** CSV `ProcessId 24416` = powershell 4688 `New Process ID 0x5f60` = Kibana
entity `j6i7ZvGKda7cXJzmUnT7qw`.

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`**
- **`powershell.exe`** (script) @ 20:13:21.086 — the full CDP cookie-theft command line; entity
  `j6i7ZvGKda7cXJzmUnT7qw`; parent.entity_id `7/uSmidEJs8WDF8jpbJyvg` (executor shell → driver root).
- **`chrome.exe`** main @ 20:13:22.488 — command_line `…chrome.exe https://www.google.com
  --remote-debugging-port=9222 --profile-directory=Default`; parent = the script powershell.
- **`chrome.exe`** children — crashpad-handler, renderers, gpu, utility (parent = chrome main);
  normal Chrome multi-process fan-out.
- **Screenshots:** `04-kibana-discover.png`, `06-kibana-discover.png`, `07-kibana-discover.png`

**`file.path` pivot on the script powershell (entity `j6i7ZvGKda7c`):** its only file writes are
`C:\Users\pb-victim\AppData\Local\Temp\__PSScriptPolicyTest_*.psm1` — PowerShell's own internal
script-policy / AMSI test files, **not** cookie output. No cookie-dump artifact is present. (Note:
the script does `Write-Host $cookies` — to stdout, not a file — so absence of a file is not by itself
proof of failure; see §5 for the fuller picture.)
- **Screenshot:** `05-kibana-filepath.png`

**Siblings (shared parent = executor shell `DF8jpbJyvg`):** `hostname.exe` @ 20:13:18.123 and
`whoami.exe` @ 20:13:18.160 — the standard scaffolding pair.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:13:19Z | UTC |
| CSV (Local) / Windows 4688 (powershell) | 20:13:19 → logged 20:13:21 | CEST (UTC+2) |
| Windows 4688 (chrome main / crashpad) | 20:13:22 | CEST |
| Kibana Discover (displayed) | 20:13:18–23 | CEST (browser-local) |

Windows/local and Elastic/UTC differ by +2h — reconciled. The gap between the CSV atomic start
(20:13:19) and process logging (20:13:21–22) covers the script's `stop-process` / `Start-Process` /
`Start-Sleep 10` sequence.

---

## 5. Finding — the technique fired but failed against Chrome 151

**Fired:** the artifact is fully present — Chrome was relaunched with `--remote-debugging-port=9222
--profile-directory=Default`, and the complete CDP `Network.getAllCookies` script executed as a
process. As a TTP observable, this node is rich and complete.

**Failed (strongly indicated):** three signals converge on the theft not succeeding.
1. **Target is Chrome 151** (`--annotation=ver=151.0.7922.138`), far past the v127 the atomic
   targets. Chrome's post-v127 mitigation refuses to expose the DevTools remote-debugging endpoint
   for the **Default** profile (the one holding real user data) — which is exactly the profile the
   script requested (`--profile-directory=Default`). The debug port most likely never opened.
2. **ExitCode -1** — a terminating error. A successful run (cookies retrieved → `Write-Host` →
   `Stop-Process`) exits 0. `-1` is consistent with the script throwing at `Invoke-WebRequest
   http://localhost:9222/json` (connection refused if the port isn't listening) or at the websocket
   `ConnectAsync` (null `webSocketDebuggerUrl`).
3. **No cookie-output artifact** — the script powershell wrote only `__PSScriptPolicyTest_*.psm1`
   files. (Caveat: cookies would go to stdout via `Write-Host`, not a file, so this is corroborating,
   not decisive on its own.)

**What this telemetry cannot show:** the exact error text, stdout, or the precise throw point.
Confirming the failure mode would need PowerShell ScriptBlock / module logging or a console
transcript — not collected here. The claim is therefore: fired, and failed on strong convergent
evidence, with the exact failure point unconfirmed.

**Cross-node conclusion (nodes 08 + 09 — the Chrome picture).** This host was seeded with fake
accounts in **Chrome only**. Neither browser-theft technique successfully collected them:
- Node 08 (`BrowserCollector.exe`) accessed Chrome's profile paths but faces app-bound encryption
  (post-v127); extraction unproven, heaviest successful activity was on the *staged* Firefox data.
- Node 09 (remote debugging) targeted the correct Default profile but Chrome 151 blocked the DevTools
  channel; exit -1.

So the emulation demonstrates **modern Chrome's defenses holding against both browser-theft paths** —
the only credentials actually collected in the run were the ones artificially staged into Firefox
(node 08). Importantly, the *artifacts fired* in both cases; detectability keys on the attempt and is
independent of whether the theft succeeded.

---

## 6. Verdict

- **Fired** (4688 present): **yes (attempt)** — powershell CDP script → `chrome.exe
  --remote-debugging-port=9222 --profile-directory=Default` at 20:13:19–22. Script PID 24416, chrome
  PID 23012. The theft did not succeed (ExitCode -1; Chrome 151 hardening — §5).
- **Defender AV detected** (1116): **no** — verified by exhaustion: the full run holds exactly two
  1116/1117 pairs (nodes 02 · ClickFix.DJS!MTB and 05 · Commandrob.A!ml); the run's last 1116 is node
  05 @ 20:11:49.
- **Defender AV acted** (1117): **no**
- **Custom rule needed:** **yes — net-new coverage (sole coverage).** The remote-debugging launch and
  CDP cookie-dump attempt are fully captured regardless of the theft's outcome.

**One-line summary:** Chrome remote-debugging cookie theft — the full CDP `Network.getAllCookies`
script and a `chrome.exe --remote-debugging-port=9222 --profile-directory=Default` launch fired, but
against Chrome 151 the technique failed (ExitCode -1; Default-profile DevTools hardening). No cookies
evidenced as exfiltrated. With node 08, modern Chrome defeated both browser-theft techniques; only the
staged Firefox data was collected. **No Defender AV detection.**
