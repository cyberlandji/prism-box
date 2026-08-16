# T1204.002 — User Execution: Malicious File

**Atomic test:** #12 — ClickFix Campaign: Abuse RunMRU to Launch mshta via PowerShell
**GUID:** `3f3120f0-7e50-4be2-88ae-54c61230cb9f`
**Magpie chain position:** 1 of 11 · **Tactic:** Execution (Delivery)

> **MITRE technique** ("User Execution: Malicious File") vs. **atomic test** ("ClickFix — abuse
> RunMRU to launch mshta") — the ClickFix social-engineering pattern is the signature delivery
> vector of Lumma Stealer, which Magpie emulates.

---

## 1. What fired (ground truth)

From [`../magpie-run1.csv`](../magpie-run1.csv):

| Execution Time (UTC) | Execution Time (Local) | Technique | Test |
|----------------------|------------------------|-----------|------|
| 2026-08-14T18:10:08Z | 2026-08-14 20:10:08 | T1204.002 | #12 ClickFix RunMRU → mshta |

The atomic writes a `RunMRU` registry value that stages an `mshta.exe` launch — emulating the
ClickFix technique, where a victim is tricked into pasting a malicious command into the Run dialog.
This node only *writes the key*; actual execution is node 02 (mshta).

---

## 2. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:10:09
- **Process command line:**
  `"powershell.exe" & {Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "atomictest" -Value "C:\Windows\System32\mshta.exe http://localhost/hello6.hta"}`
- **Creator / parent process:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (the driver)
- **Mandatory Label:** High Mandatory Level
- **Screenshot:** `01-security-4688.png`

The command writes the RunMRU key pointing at `mshta.exe http://localhost/hello6.hta` — the staged
delivery. This is a **registry-write behavior** surfaced here as a process-creation event (the
PowerShell that performs the write).

---

## 3. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`**
- **event.category:** process (the PowerShell performing the write) — the registry write itself
  also appears under `event.category: registry` (registry.path = the RunMRU key)
- **@timestamp (UTC):** 2026-08-14 18:10:09.151Z (20:10:09.151 local)
- **process.command_line:** the RunMRU Set-ItemProperty (matches the 4688)
- **process.parent.entity_id:** `7/uSmidEJs8WDF8jpbJyvg` → resolves to the driver root (see `00-`)
- **Screenshot:** `02-kibana-discover.png`

**Security → Alerts:** no alert — no custom rule authored yet; behavioral protection suite is
licence-gated (telemetry + malware NGAV only).

---

## 4. Timeline reconciliation (+2h)

| Surface | Timestamp | Zone |
|---------|-----------|------|
| CSV (UTC) | 18:10:08Z | UTC |
| CSV (Local) / Windows 4688 | 20:10:09 | CEST (UTC+2) |
| Kibana @timestamp | 18:10:09.151Z | UTC |

Windows/local and Elastic/UTC differ by +2h — same event, reconciled. (The 1s CSV-vs-4688 offset
is the atomic firing → process logging gap.)

---

## 5. Verdict

- **Fired** (4688 present): **yes** — RunMRU key-write at 20:10:09
- **Defender AV detected** (1116): **no** — verified: no 1116 in the Defender operational log
  between the driver launch (20:10:00) and the first detection at 20:10:42. That first 1116
  (`Trojan:Win32/ClickFix.DJS!MTB`) carries node 02's `cmd.exe /c mshta.exe about:<hta...>`
  command line and therefore attributes to **T1218.005 (node 02)**, not this node.
- **Defender AV acted** (1117): **no** (for this node)
- **Custom rule needed:** **yes — net-new coverage (sole coverage).** Defender did not detect the
  RunMRU-write delivery stage; a rule keying on the RunMRU registry modification (an `mshta.exe`
  value written to the Run-dialog MRU) is the only coverage for this node.

**One-line summary:** ClickFix RunMRU delivery executed and was captured in endpoint telemetry
(process + registry) but produced **no Defender AV detection** — the custom detection rule is the
sole coverage for this delivery-stage technique.

---

## Note — Defender 1116/1117 attribution

The first Defender detection/response pair (1116 @ 20:10:42 → 1117 @ 20:11:03) does **not** belong
to this node. Verified against the full Defender operational log: nothing fired between 20:10:00 and
20:10:42 except benign 2010 (cloud-protection) events. The RunMRU write at 20:10:09 passed
undetected. Detection attribution for the 20:10:42 event moves to node 02 (T1218.005 mshta).
