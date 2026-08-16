# T1555.003 — Credentials from Password Stores: Credentials from Web Browsers

**Atomic test:** #16 — BrowserStealer (Chrome / Firefox / Microsoft Edge)
**GUID:** `6f2c5c87-a4d5-4898-9bd1-47a55ecaf1dd`
**Magpie chain position:** 8 of 11 · **Tactic:** Credential Access

> **MITRE technique** ("Credentials from Password Stores: Credentials from Web Browsers") vs.
> **atomic test** ("BrowserStealer — Chrome / Firefox / Microsoft Edge") — a powershell wrapper
> stages test credential files into the Firefox profile, then launches `BrowserCollector.exe`, an
> **unsigned** stealer that sweeps browser credential stores. This is the credential-access heart of
> the emulation. The powershell staging is Firefox-only; the collection itself is a broad
> multi-browser sweep, resolved from `file.path` (§5).

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test | ProcessId | ExitCode |
|----------------------|------------------------|-----------|------|-----------|----------|
| 2026-08-14T18:12:54Z | 2026-08-14 20:12:54 | T1555.003 | #16 BrowserStealer (Chrome / Firefox / Edge) | 21700 | 0 |

A three-process chain: powershell (Firefox profile staging + launch) → `BrowserCollector.exe` (the
stealer) → `cmd.exe /c pause`. Exit code 0 = the atomic's self-check passed. The CSV `ProcessId`
(21700) is the root powershell.

---

## 2. Endpoint evidence (Windows raw log)

Three process-creation records were captured — the full chain.

**Process 1 — `powershell.exe` (root / staging):**
- **Logged (local):** 20:12:54
- **New process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (New Process ID `0x54c4` = **21700** = CSV ProcessId)
- **Process command line** (Firefox profile staging → BrowserCollector launch):
  ```
  "powershell.exe" & {$profile = (Gci -filter "*default-release*" -path $env:Appdata\Mozilla\Firefox\Profiles\).FullName
  Copy-Item $profile\key4.db -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads\" > $null
  Copy-Item $profile\logins.json -Destination "C:\AtomicRedTeam\atomics\..\ExternalPayloads\" > $null
  Remove-Item $profile\key4.db > $null
  Remove-Item $profile\logins.json > $null
  Copy-Item "$env:C:\AtomicRedTeam\atomics\T1555.003\src\key4.db" -Destination $profile\ > $null
  Copy-Item "$env:C:\AtomicRedTeam\atomics\T1555.003\src\logins.json" -Destination $profile\ > $null
  cd "$env:C:\AtomicRedTeam\atomics\T1555.003\bin\"
  .\BrowserCollector.exe}
  ```
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x143c` = 5180 — the atomic executor shell)
- **Token Elevation Type:** `%%1937` · **Mandatory Label:** High Mandatory Level
- **Screenshot:** `01-security-4688.png`

**Process 2 — `BrowserCollector.exe` (stealer):**
- **Logged (local):** 20:12:55
- **New process:** `C:\AtomicRedTeam\atomics\T1555.003\bin\BrowserCollector.exe` (New Process ID `0x3598` = **13720**)
- **Process command line:** `"C:\AtomicRedTeam\atomics\T1555.003\bin\BrowserCollector.exe"`
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (Creator Process ID `0x54c4` = 21700 — the root powershell above)
- **Token Elevation Type:** `%%1937` · **Mandatory Label:** High Mandatory Level
- **Screenshot:** `02-security-4688.png`

**Process 3 — `cmd.exe /c pause`:**
- **Logged (local):** 20:12:57
- **New process:** `C:\Windows\System32\cmd.exe` (New Process ID `0x27b4` = **10164**)
- **Process command line:** `C:\Windows\system32\cmd.exe /c pause`
- **Creator / parent process:** `C:\AtomicRedTeam\atomics\T1555.003\bin\BrowserCollector.exe` (Creator Process ID `0x3598` = 13720 — BrowserCollector above)
- **Token Elevation Type:** `%%1937` · **Mandatory Label:** High Mandatory Level
- **Screenshot:** `03-security-4688.png`

**Chain:** executor shell (5180) → powershell (21700) → `BrowserCollector.exe` (13720) →
`cmd.exe /c pause` (10164).

**Identity cross-check:** CSV `ProcessId 21700` = powershell 4688 `New Process ID 0x54c4` = Kibana
entity `8JK5Puyr+k3wIiB27bq4Ew`.

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`**

Chain entities:
- **`powershell.exe`** (root) @ 20:12:54.403 — the Firefox-staging command line; entity
  `8JK5Puyr+k3wIiB27bq4Ew`; parent.entity_id `7/uSmidEJs8WDF8jpbJyvg` (executor shell → driver root,
  see `00-`). Its `file` events (the `Copy-Item` / `Remove-Item` on the Firefox profile) and library
  loads carry this entity.
- **`BrowserCollector.exe`** @ 20:12:55.172 (process start) — entity `wUGoPD64k0U0SXZgM8I8TQ`;
  parent.entity_id `8JK5Puyr+k3w…` (the root powershell); executable
  `C:\AtomicRedTeam\atomics\T1555.003\bin\BrowserCollector.exe`.
- **`cmd.exe /c pause`** @ 20:12:57.520 — entity `NaVJ+Oazg1wUhlhAdDVT5Q`; parent.entity_id
  `wUGoPD64k0U0…` (BrowserCollector).
- **Screenshots:** `04-kibana-discover.png`, `05-kibana-discover.png`, `06-kibana-discover.png`, `07-kibana-discover.png`

**Unsigned binary (key signal):** `BrowserCollector.exe` has `code_signature.exists: false`,
`code_signature.trusted: (null)` — the **first unsigned executable** in the chain. Every prior
technique process was a signed Microsoft binary (powershell, cmd, reg). An unsigned exe running from
`C:\AtomicRedTeam\…\bin\` is a strong deviation.

**Collection scope (`file.path` pivot on entity `wUGoPD64k0U0`):** the burst of `event.category:
file` events across ~20:12:55.9 → 20:12:57.6 carries `file.path` values showing a **broad
multi-browser sweep** under `C:\Users\pb-victim\AppData\Local\`:
- `Mozilla\…` (Firefox) — the highest event volume
- `Google(x86)\…` (Chrome)
- `Chromium\User…`
- `Yandex\Yande…`
- (plus further browser locations)
- `Temp\ww5o8id…` — the collector's own scratch/output directory (not a browser; where it stages what it gathers)
- **Screenshots:** `08-kibana-filepath.png`, `09-kibana-filepath.png`

**System noise:** `services.exe` `[authentication, session]` @ 20:12:56.225 and `svchost.exe -k
wsappx` @ 20:12:55.776 — benign OS activity, unrelated.

**Security → Alerts:** no alert — no custom rule authored yet; behavioural protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:12:54Z | UTC |
| CSV (Local) / Windows 4688 (powershell) | 20:12:54 | CEST (UTC+2) |
| Windows 4688 (BrowserCollector) | 20:12:55 | CEST |
| Windows 4688 (cmd /c pause) | 20:12:57 | CEST |
| Kibana Discover (displayed) | 20:12:54–57 | CEST (browser-local) |

Windows/local and Elastic/UTC differ by +2h — same events, reconciled. The ~3s spread across the
chain is powershell → BrowserCollector → its file collection → `cmd /c pause`.

---

## 5. Finding — staging (Firefox-only) vs collection (broad multi-browser)

**Two distinct actors, easy to conflate — and the `file.path` data separates them.**

1. **The powershell does Firefox-only *setup*.** It backs up the real Firefox `key4.db` /
   `logins.json`, removes them, then drops the atomic's *own* test `key4.db` / `logins.json` (from
   `T1555.003\src\`) into the profile — giving the stealer known, readable credentials to find. This
   step touches only `Mozilla\Firefox\Profiles`. The "only Firefox" reading is correct **for this
   step**.

2. **`BrowserCollector.exe` collection is a broad sweep — not Firefox-only.** Its `file.path` values
   span Mozilla (Firefox), Google (Chrome), Chromium, Yandex, and further Chromium-family locations.
   Firefox shows the **most** file activity, which is consistent with it being the only browser the
   atomic staged with readable test credentials — the collector found real data there and did real
   work; elsewhere it mostly probed.

**Access ≠ extraction — the crux for the seed.** This host was seeded with fake accounts in **Chrome
only** (Firefox/Edge/Opera/Yandex may hold incidental cookies but no planted credentials). The
`file.path` proves BrowserCollector *accessed* Chrome's location, not that it *extracted* the seeded
credentials. Chrome v127+ app-bound encryption is designed to defeat exactly this kind of profile
read, so the thin Chrome activity despite the Chrome seed is expected — and successful extraction is
not evidenced by these logs. That hardening is the subject of node 09 (T1539); the two nodes should
be read together for the full Chrome picture.

**Output path bridges to the exfil chain.** BrowserCollector writes to `…\AppData\Local\Temp\ww5o8id…`
— its staging directory for gathered data. That is the input to node 10 (T1005, stage to zip) and
ultimately node 11 (T1041, exfil).

**Unsigned-binary signal.** `BrowserCollector.exe` is the first `code_signature.exists: false`
process in the chain. Combined with a broad browser-profile sweep and a `cmd /c pause` child, it
forms a high-fidelity behavioural cluster — recorded here as a telemetry observation.

---

## 6. Verdict

- **Fired** (4688 present): **yes** — powershell (Firefox staging) → `BrowserCollector.exe` (broad
  multi-browser sweep) → `cmd /c pause`, at 20:12:54–57. Root PID 21700, BrowserCollector PID 13720.
- **Defender AV detected** (1116): **no** — verified by exhaustion: the full run holds exactly two
  1116/1117 pairs (nodes 02 · ClickFix.DJS!MTB and 05 · Commandrob.A!ml); the run's last 1116 is
  node 05 @ 20:11:49. An unsigned credential stealer ran here undetected at the NGAV tier.
- **Defender AV acted** (1117): **no**
- **Custom rule needed:** **yes — net-new coverage (sole coverage).**

**One-line summary:** browser-credential theft — a Firefox-staging powershell launches the unsigned
`BrowserCollector.exe`, which sweeps multiple browser profiles (Firefox heaviest, plus Chrome /
Chromium / Yandex) and stages output to `Temp`, with **no Defender AV detection**. Collection scope
is broad (from `file.path`), but access ≠ extraction — the seeded Chrome credentials sit behind
v127+ app-bound encryption, which node 09 addresses.
