# Phase A - Prerequisites

**Goal:** prove the logs can see attacks, snapshot WIN11-01, and install the validator.
Save this phase's screenshots in **this folder** (PNG).

| Step | Check | How | Result | Screenshot (save here) | Date |
|------|-------|-----|:------:|------------------------|------|
| 1 | Sysmon logs reach Splunk | `index=main source="*Sysmon/Operational" EventCode=1 \| head 5` | ✅ 5 EID-1 events, WIN11-01 | `prereq-1-sysmon-events.png` | 2026-07-18 |
| 2 | Clean parsed fields | `... EventCode=1 \| table _time host Image CommandLine ParentImage` | ✅ 984 events, Image/CmdLine populated | `prereq-2-clean-fields.png` | 2026-07-18 |
| 3 | Snapshot WIN11-01 taken | VM snapshot **before** any atomic test | ✅ "Pre-AtomicRedTeam" | `prereq-3-snapshot.png` | 2026-07-18 |
| 4 | Atomic Red Team installed | `Invoke-AtomicTest T1059.001 -ShowDetails` lists the steps | ✅ atomics in `C:\AtomicRedTeam\atomics` | `prereq-4-art-installed.png` | 2026-07-18 |

**Notes** _(result counts, anything you had to fix - e.g. restarted SplunkForwarder):_
- Step 1: 5 EID-1 events confirmed from WIN11-01 (Splunk forwarder's own processes - normal noise).
- Step 2: fields were **not extracted** - `EventCode=1` returned 0 results; `spath` showed blank `Image`/`CommandLine`; diagnostic showed sourcetype `XmlWinEventLog` with `EventCode`/`EventID`/`Image`/`CommandLine` **all blank**.
- **Root cause:** the Splunk Add-on for Sysmon rides on top of the **Splunk Add-on for Microsoft Windows (`Splunk_TA_windows`)** - the base parser that turns the `XmlWinEventLog` sourcetype into `EventCode`/`EventID`/`Image`/... fields. That base add-on was missing on **DC01 (the Splunk server)**.
- **Fix:** install `Splunk_TA_windows` on DC01 + restart Splunk. Extractions are search-time, so they apply to already-indexed events (no re-forwarding needed).
- ✅ **Confirmed working:** after installing the Splunk Add-on for Microsoft Windows on DC01 + restart, `EventCode=1` returns **984 events** with `Image`, `CommandLine`, `ParentImage` all populated.
- Step 4 (ART): WIN11-01 is isolated (Host-Only) → no internet, so NuGet/`Install-Module` failed. Workaround: added a 2nd VirtualBox adapter as **NAT** (power-cycled) to install ART + atomics, then disabled it to re-isolate. Atomics run offline once downloaded (`C:\AtomicRedTeam`).
- Gotcha: a **new** PowerShell window reset the per-process execution policy, so `powershell-yaml` was blocked ("running scripts is disabled"). Fixed with `Set-ExecutionPolicy Bypass -Scope CurrentUser -Force`. Then the install script + `Install-AtomicRedTeam -getAtomics` succeeded; `-ShowDetails` lists the T1059.001 tests. ✅ **Phase A complete.**
