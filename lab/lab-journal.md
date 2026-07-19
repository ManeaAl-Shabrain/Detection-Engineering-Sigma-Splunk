# Detection Engineering - Lab Journal (index)

Central index for the hands-on validation. Each phase has its **own file and folder**
below - do the work, drop that phase's screenshots in its folder, tick its boxes.

| | |
|---|---|
| **Analyst** | Manea Al-Shabrain |
| **Started** | 2026-07-18 |
| **Lab** | SOC home lab - Splunk + Sysmon (WIN11-01, DC01), Kali attacker |
| **VM snapshot** | ✅ taken before atomic tests - name: `Pre-AtomicRedTeam` |

## Phases

| Phase | What | File | Status |
|-------|------|------|:------:|
| **A** | Prerequisites - data source, clean fields, snapshot, install ART | [phase-A-prerequisites/](phase-A-prerequisites/phase-A.md) | ✅ |
| **B** | Detection loop - 8 techniques atomic-tested & detected | [phase-B-detections/](phase-B-detections/phase-B.md) | ✅ 8/8 (7 detected · 1 prevented) |
| **C** | Tuning - false positives found & removed | [phase-C-tuning/](phase-C-tuning/phase-C.md) | ✅ 0 FPs on baseline |
| **D** | Alerts + wrap-up | [phase-D-alerts/](phase-D-alerts/phase-D.md) | ✅ 3 alerts live (1 fired) · report + README done |

- Final coverage scorecard → [../coverage-matrix.md](../coverage-matrix.md)
- Raw exports (CSV, .conf) → [exports/](exports/)

## Progress log (newest first)

- **2026-07-19** - **Phase D ✅ - PROJECT COMPLETE.** Report written and exported to PDF (`report/Detection-Engineering-Report.pdf` + styled HTML); coverage matrix finalized; README **Results** + **What I learned** filled in. All 4 phases closed: 8/8 techniques addressed (7 detected · 1 prevented), 0 baseline FPs, 3 alerts live (1 fired).
- **2026-07-18** - **Phase C ✅:** benign baseline (Get-Process/Service, Notepad/Calc, ipconfig, gpupdate) → consolidated FP check returned **0 events**. No false positives; rules deployable. Inline tuning (cmd.exe FN, field mappings, EID 10 gap) documented in phase-C.
- **2026-07-18** - **Phase D:** 3 scheduled alerts deployed (Encoded PS, Shadow Copies, Brute Force) - every 5 min, trigger on results>0. Encoded-PowerShell alert **fired** (Trigger History 16:55:05). Skipped LSASS alert (prevented). Next: benign baseline → package.
- **2026-07-18** - **#8 T1110 ✅ - PHASE B COMPLETE (8/8 addressed: 7 detected · 1 prevented).** Kali NetExec SMB brute force → 8× 4625 → threshold rule fired (1 row, 8 fails from 192.168.10.30).
- **2026-07-18** - **#3 T1003.001 - PREVENTED (defense-in-depth win).** Enabled Sysmon ProcessAccess (closed a telemetry gap); LSASS dump blocked at launch by ASR (even with RTP off) + LSA Protection. Documented as prevention, not detection - prevention erased the telemetry. Only #8 (brute force) left.
- **2026-07-18** - Detection **#7 T1218** ✅ (6/8). Ran certutil (encode/decode/urlcache) + regsvr32 squiblydoo manually; downloads failed offline but all 4 caught on command line. Parent = powershell.exe (FP-tuning pivot).
- **2026-07-18** - Detection **#5 T1136.001** ✅ (5/8). Enabled `User Account Management` auditing, ran all Windows-applicable atomics (4/5/8/9) → 3× event 4720 detected. Two lessons: atomic `-TestNumbers` spans platforms (use no `-TestNumbers`), and this lab's Security log is classic WinEventLog so the field is `Account_Name`, not `TargetUserName` - SPL [5]/[8] adapted.
- **2026-07-18** - Detection **#6 T1490** ✅ (4/8). `vssadmin delete shadows /all /quiet` - the command itself failed (no shadows present, exit 1) but the detection fired anyway: we alert on behaviour, not outcome.
- **2026-07-18** - Detection **#4 T1053.005** ✅ (3/8). Atomic created 2 scheduled tasks; detection caught both `schtasks /create` events. Validated the pre-emptive `cmd.exe` fix - without it the rule would have missed its own atomic (false negative).
- **2026-07-18** - Detection **#2 T1547.001** ✅ (2/8). Atomic `-TestNumbers 1` ("Reg Key Run") → Sysmon EID 13 caught `reg.exe` writing `...\CurrentVersion\Run\Atomic Red Team`. All session screenshots filed into phase-A (4) / phase-B (5).
- **2026-07-18** - 🎉 **First detection fired (1/8).** Controlled encoded PowerShell on WIN11-01 → Splunk rule #1 returned 1 event (TP); `Get-Process` = no FP. Full loop proven end-to-end.
- **2026-07-18** - **Phase A complete ✅.** Snapshot "Pre-AtomicRedTeam" taken; Atomic Red Team installed (fixed internet via a temporary NAT adapter + set execution policy for CurrentUser). Atomics at `C:\AtomicRedTeam\atomics`. Moving to **Phase B · Detection #1** (encoded PowerShell).
- **2026-07-18** - Phase A Steps 1-2 ✅. Telemetry flowing; fixed blank fields by installing `Splunk_TA_windows` on DC01 (the base `XmlWinEventLog` parser under the Sysmon add-on). `EventCode=1` now returns 984 events with clean `Image`/`CommandLine`. Next: snapshot + install Atomic Red Team.
- **2026-07-18** - Repo + phase-based lab structure created. Starting **Phase A · Step 1** (confirm Sysmon → Splunk).
