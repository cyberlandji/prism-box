# T1005 — Data from Local System

**Atomic test:** #1 — Search files of interest and save them to a single zip file (Windows)
**GUID:** `d3d9af44-b8ad-4375-8b0a-4bff4b7e419c`
**Magpie chain position:** 10 of 11 · **Tactic:** Collection

> **MITRE technique** ("Data from Local System") vs. **atomic test** ("Search files of interest and
> save them to a single zip file") — a powershell script recursively searches `C:\Users` for document
> extensions (`.doc` / `.docx` / `.txt`) and `Compress-Archive`s the matches into a staging zip. This
> is document collection — a **separate loot stream** from node 08's browser-credential theft, not a
> repackaging of it (§5).

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:15:47Z | 2026-08-14 20:15:47 | T1005 | #1 Search files & save to a zip | 10280 | 0 |

The script recursively enumerates `C:\Users` for `.doc` / `.docx` / `.txt`, then archives the matches
to `…\ExternalPayloads\T1005\data.zip`. Exit code 0 = success; the zip was written (evidenced in §3).
The CSV `ProcessId` (10280) is the script's powershell.

---

## 2. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:15:47
- **New process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (New Process ID `0x2828` = **10280** = CSV ProcessId)
- **Process command line (abridged):**
  ```
  "powershell.exe" & {$startingDirectory = "C:\Users\"
  $outputZip = "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1005\"
  $fileExtensionsString = ".doc, .docx, .txt"
  $fileExtensions = $fileExtensionsString -split ", "
  New-Item -Type Directory $outputZip -ErrorAction Ignore -Force | Out-Null
  Function Search-Files { param([string]$directory)
    $files = Get-ChildItem -Path $directory -File -Recurse | Where-Object { $fileExtensions -contains $_.Extension.ToLower() }
    return $files }
  $foundFiles = Search-Files -directory $startingDirectory
  if ($foundFiles.Count -gt 0) {
    $foundFilePaths = $foundFiles.FullName
    Compress-Archive -Path $foundFilePaths -DestinationPath "$outputZip\data.zip"
    Write-Host "Zip file created: $outputZip\data.zip"
  } else { Write-Host "No files found with the specified extensions." }}
  ```
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell)
- **Token Elevation Type:** `%%1937` · **Mandatory Label:** High Mandatory Level
- **Screenshots:** `01-security-4688_1.png`, `01-security-4688_2.png`

**Identity cross-check:** CSV `ProcessId 10280` = 4688 `New Process ID 0x2828` = Kibana
`process.entity_id ovnt7QhzEEZNDBKcCH13pA`.

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`**
- **`powershell.exe`** (script) @ 20:15:47.187 — the full T1005 collection command line; entity
  `ovnt7QhzEEZNDBKcCH13pA`; parent.entity_id `7/uSmidEJs8WDF8jpbJyvg` (executor shell → driver root).
- **`conhost.exe`** @ 20:15:47.284 — entity `eGrn0rnbBGNYj9pWFgaNhA`; parent = the script powershell — console host, benign.
- **Screenshots:** `02-kibana-discover.png`, `04-kibana-filepath.png`

**Collection output — the zip write (success evidence):** a `event.category: file` event at
**20:15:48.826** by the script powershell (entity `ovnt7QhzEEZN`) with
`file.path: C:\AtomicRedTeam\ExternalPayloads\T1005\data.zip`. The archive was created, so
`$foundFiles.Count > 0` — the sweep found and bundled at least some documents under `C:\Users`.
- **Screenshot:** `03-kibana-filepath.png`

**PowerShell scaffolding files:** the script's other early file writes are
`…\AppData\Local\Temp\__PSScriptPolicyTest_*.psm1` — PowerShell's own internal script-policy / AMSI
test files, not loot.

**Siblings (shared parent = executor shell `DF8jpbJyvg`):** `hostname.exe` @ 20:15:46.680 and
`whoami.exe` @ 20:15:46.791 — the standard scaffolding pair.

**System noise:** `VSSVC.exe` @ 20:15:56.456 (Volume Shadow Copy Service — incidental;
`Compress-Archive` does not use VSS) and `lsass.exe` / `services.exe` `[authentication, session]`
@ 20:16:06.034 (these sit at node 11's time, not node 10's). Both unattributed to this technique.

**Boundary note:** an unidentified `powershell.exe` (+ conhost) appears at ~20:15:23, before node
10's scaffolding; it is not identified from these captures. The node 09 → node 10 gap is ~2.5 min —
if that gap matters, this process's command line is where the explanation would be.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:15:47Z | UTC |
| CSV (Local) / Windows 4688 | 20:15:47 | CEST (UTC+2) |
| Kibana process (stored) | 18:15:47.187Z | UTC |
| Kibana zip write (stored) | 18:15:48.826Z | UTC |
| Kibana Discover (displayed) | 20:15:47–48 | CEST (browser-local) |

Windows/local and Elastic/UTC differ by +2h — reconciled.

---

## 5. Finding — document collection (succeeded), a separate stream from node 08

**What it collected.** The `$startingDirectory` is `C:\Users` and the extensions are
`.doc` / `.docx` / `.txt` — this is a recursive **document** sweep across all user profiles, archived
to `ExternalPayloads\T1005\data.zip`. It is **not** a repackaging of node 08's browser loot
(BrowserCollector's `Temp\ww5o8id…` output); the two are independent collection streams — node 08
= browser credentials, node 10 = local documents — both feeding the general staging concept.

**It succeeded — and the success is directly evidenced.** Unlike node 09 (fired but failed), node 10
fired and completed: the `data.zip` file-write at 20:15:48.826 confirms the archive was created, which
means the sweep matched at least one document under `C:\Users`. The observable is complete — a
powershell recursively enumerating user directories for document extensions and `Compress-Archive`
to a staging zip is a classic collection/staging signature, fully captured in the command line, with
the output path confirmed in `file.path`.

**Bridge to node 11.** `data.zip` is the staged collection output and a candidate for the exfil at
node 11 (T1041) — to be confirmed there.

---

## 6. Verdict

- **Fired** (4688 present): **yes** — powershell document sweep of `C:\Users` → `Compress-Archive`
  to `ExternalPayloads\T1005\data.zip` at 20:15:47, PID 10280. Collection **succeeded** (zip write
  evidenced at 20:15:48.826).
- **Defender AV detected** (1116): **no** — verified by exhaustion: the full run holds exactly two
  1116/1117 pairs (nodes 02 · ClickFix.DJS!MTB and 05 · Commandrob.A!ml); the run's last 1116 is node
  05 @ 20:11:49.
- **Defender AV acted** (1117): **no**
- **Custom rule needed:** **yes — net-new coverage (sole coverage).** The document sweep and staging
  archive passed undetected.

**One-line summary:** local document collection — a powershell recursively searched `C:\Users` for
`.doc` / `.docx` / `.txt` and `Compress-Archive`d the matches to `ExternalPayloads\T1005\data.zip`;
the collection succeeded (zip write evidenced at 20:15:48.826). A separate loot stream from node 08's
browser theft, with **no Defender AV detection**.
