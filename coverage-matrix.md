# Detection Coverage Matrix

Coverage is the headline metric of detection engineering. This matrix maps each
technique in the pack to its rule, its Atomic Red Team validation test, and its
tuning status.

**Legend:** ✅ done · 🛡️ prevented by host hardening (a valid defensive outcome)

| # | Technique | ATT&CK ID | Tactic | Data source | Rule written | Atomic test | Detected | False positives |
|---|-----------|-----------|--------|-------------|:---:|:---:|:---:|-----------------|
| 1 | Encoded PowerShell | T1059.001 | Execution | Sysmon EID 1 | ✅ | ✅ | ✅ | None on baseline; `-e` broad → tune in Phase C |
| 2 | Registry Run-Key persistence | T1547.001 | Persistence | Sysmon EID 13 | ✅ | ✅ | ✅ | None on atomic; exclude signed installers |
| 3 | LSASS credential access | T1003.001 | Credential Access | Sysmon EID 10 | ✅ | ✅ | 🛡️ Prevented | Blocked by ASR + LSA Protection; ProcessAccess telemetry gap closed |
| 4 | Scheduled task creation | T1053.005 | Persistence / PrivEsc | Sysmon EID 1 | ✅ | ✅ | ✅ | Broadened `cmd /c` → `cmd.exe` (was a false negative) |
| 5 | Create local account | T1136.001 | Persistence | Security 4720 | ✅ | ✅ | ✅ | Needed auditpol enable; correlate w/ change tickets |
| 6 | Delete volume shadow copies | T1490 | Impact | Sysmon EID 1 | ✅ | ✅ | ✅ | None in lab; allow backup software in prod |
| 7 | LOLBin abuse (certutil/regsvr32/rundll32) | T1218 | Defense Evasion | Sysmon EID 1 | ✅ | ✅ | ✅ | Scope by ParentImage (powershell/office) in prod |
| 8 | SMB / RDP brute force | T1110 | Credential Access | Security 4625 | ✅ | ✅ | ✅ | Threshold ≥5/5min; whitelist service accts/jump hosts |

**Tactics covered:** Execution · Persistence · Privilege Escalation · Defense Evasion · Credential Access · Impact - 6 MITRE ATT&CK tactics.

## Status - complete

All 8 techniques were validated on the isolated Splunk + Sysmon lab (2026-07-18):

- **7 detected, 1 prevented** - T1003.001 was blocked by ASR + LSA Protection before it could generate any telemetry (documented as a defense-in-depth win, not a failed detection).
- **0 false positives** on a benign-activity baseline → all rules confirmed deployable.
- **Top 3 rules deployed** as scheduled Splunk alerts; the Encoded-PowerShell alert is confirmed firing.

Attack + detection evidence for every technique lives in its phase folder under
[`lab/`](lab/lab-journal.md) (e.g. `lab/phase-B-detections/`), and the full write-up -
objective, methodology, walk-throughs, tuning, lessons - is in
[`report/Detection-Engineering-Report.pdf`](report/Detection-Engineering-Report.pdf).
