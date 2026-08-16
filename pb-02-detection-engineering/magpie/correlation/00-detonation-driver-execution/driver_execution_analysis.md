# 00 — Operation Start (Detonation Driver Execution)

**Not a MITRE technique.** This is the root process of the Magpie operation — the driver script
launch from which every subsequent technique (nodes 01–11) descends. Captured to establish
**operation t-zero** and **provenance**.

---

## 1. Why this is captured first

Two distinct timelines matter in any intrusion:

- **Operation timeline** — when the adversary's activity actually begins.
- **Observable timeline** — when defensive telemetry first records something.

They are not the same. In a real intrusion the operation may begin minutes, hours, or days
before the first observed technique (staging, unseen initial access, dwell time). Anchoring "when
it started" to the first alert gets the incident timeline wrong.

This folder captures the **true operation start** — the moment the detonation driver was launched —
which precedes the first technique (T1204.002). It also establishes **provenance**: every
downstream event traces its ancestry to this one process, proving the run was a single,
deliberate, attributable operation rather than incidental activity.

---

## 2. The root process (ground truth)

Launched:

```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -File C:\atomic\magpie-detonation-driver.ps1
```

| Fact | Value |
|------|-------|
| Process | `powershell.exe` (`process.pe.original_file_name`: PowerShell.EXE) |
| Command line | `-ExecutionPolicy Bypass -File C:\atomic\magpie-detonation-driver.ps1` |
| **process.entity_id (tree root)** | `It2eBw9Eejif4DueKbOGIA` |
| Integrity | High Mandatory Level (launched from elevated prompt) |
| Host | DESKTOP-EB94L4C |

---

## 3. Endpoint evidence (Windows raw log)

**Security log — Event 4688 (process creation):**
- **Logged (local):** 20:10:00
- **Command line:** `"...powershell.exe" -ExecutionPolicy Bypass -File C:\atomic\magpie-detonation-driver.ps1`
- **Mandatory Label:** High Mandatory Level
- **Screenshot:** `01-security-4688.png`

---

## 4. SIEM evidence (Elastic / Kibana)

**Discover — `event.module: "endpoint"`, `event.category: process`**
- **@timestamp (UTC):** 2026-08-14 18:10:00.169Z (20:10:00.169 local)
- **process.entity_id:** `It2eBw9Eejif4DueKbOGIA`  ← ancestry root for the whole chain
- **process.name / pe.original_file_name:** powershell.exe / PowerShell.EXE
- **Screenshot:** `02-kibana-discover.png`

---

## 5. The operation-vs-observable gap

| Event | Time (local) | Time (UTC) |
|-------|--------------|------------|
| **Driver launched (operation start)** | 20:10:00 | 18:10:00Z |
| First technique fired (T1204.002, node 01) | 20:10:08 | 18:10:08Z |
| **Gap** | **~8 seconds** | — |

The ~8s gap is the driver's session-setup running before the first technique detonates
(Set-ExecutionPolicy → Import-Module → 5s pause → firing loop). Small here by design; in a real
intrusion the equivalent gap is the invisible early operation. The point stands: **the first
observed technique is not the start of the operation.**

---

## 6. Provenance note

`process.entity_id: It2eBw9Eejif4DueKbOGIA` is the ancestry root. Every technique folder (01–11)
records `process.parent.entity_id` that resolves — directly or up the chain — to this process.
This is what makes the eleven correlated events provably **one controlled operation**: a defined
t-zero, a known driver, and a single traceable process tree.

**Honest fidelity note:** the driver was launched from an elevated (admin) prompt, so the entire
chain runs at High integrity. Real Lumma delivery typically begins at Medium (normal-user)
integrity — a deliberate lab simplification, documented rather than hidden.
