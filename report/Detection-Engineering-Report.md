# Detection Engineering Report - Sigma → Splunk (+ KQL)

**Author:** Manea Al-Shabrain
**Date:** 2026-07-18
**Environment:** Isolated home SOC lab (VirtualBox, Host-Only network, domain `SOCLAB`)

- **DC01** - Splunk Enterprise (indexer + search head), `index=main`
- **WIN11-01** - Sysmon + Splunk Universal Forwarder; Atomic Red Team
- **KALI-01** - attacker (NetExec)

> Export to PDF (`Detection-Engineering-Report.pdf`) and link from the repo README.

---

## 1. Objective

Engineer a threat-informed detection pack covering **8 MITRE ATT&CK techniques across 6
tactics**; author each rule once in vendor-neutral **Sigma**; convert to **Splunk SPL**
(and **KQL**); validate every rule against a real **Atomic Red Team** test; and tune out
false positives before deploying the strongest rules as alerts.

## 2. Methodology - the detection lifecycle

Every technique ran through the same five-step loop:

1. **Data source** - identify which log sees the behaviour (Sysmon EID or Windows Security event).
2. **Detection** - author the Sigma rule.
3. **Test & validate** - execute the technique (Atomic Red Team or an equivalent live command) and confirm the rule fires.
4. **Tune** - run a benign baseline; remove/scope anything that alerts on normal activity.
5. **Deploy** - save the highest-value rules as scheduled Splunk alerts; track coverage.

**Prerequisite fix - field extraction.** Sysmon data initially arrived as the generic
`XmlWinEventLog` sourcetype with *no* parsed fields (`Image`, `CommandLine`, `EventCode`
all blank). Installing the **Splunk Add-on for Microsoft Windows** (the base
`XmlWinEventLog` parser) alongside the **Splunk Add-on for Sysmon** on DC01 produced clean
fields - without which no rule can match.

## 3. Coverage matrix

| # | Technique | ATT&CK | Tactic | Data source | Result |
|---|-----------|--------|--------|-------------|--------|
| 1 | Encoded PowerShell | T1059.001 | Execution | Sysmon EID 1 | ✅ Detected |
| 2 | Registry Run-Key | T1547.001 | Persistence | Sysmon EID 13 | ✅ Detected |
| 3 | LSASS credential access | T1003.001 | Credential Access | Sysmon EID 10 | 🛡️ Prevented |
| 4 | Scheduled task | T1053.005 | Persistence / PrivEsc | Sysmon EID 1 | ✅ Detected |
| 5 | Create local account | T1136.001 | Persistence | Security 4720 | ✅ Detected |
| 6 | Delete shadow copies | T1490 | Impact | Sysmon EID 1 | ✅ Detected |
| 7 | LOLBin abuse | T1218 | Defense Evasion | Sysmon EID 1 | ✅ Detected |
| 8 | SMB brute force | T1110 | Credential Access | Security 4625 | ✅ Detected |

**Headline:** 8/8 addressed - **7 detected, 1 prevented**, across **6 ATT&CK tactics**; **0 false positives** on the benign baseline.

## 4. Detailed walk-throughs

### 4.1 T1059.001 - Encoded PowerShell (the baseline loop)
- **Behaviour:** attackers base64-encode PowerShell (`-EncodedCommand`) to hide intent from casual log review.
- **Attack:** `powershell.exe -EncodedCommand <base64>` (benign payload, run offline).
- **Detection (SPL):** Sysmon EID 1 where `Image` is powershell/pwsh and `CommandLine` contains `-enc` / `-encodedcommand` / `-ec` / `-e`.
- **Evidence:** 1 event - `...powershell.exe -EncodedCommand VwByAGkA...`, `User=SOCLAB\Administrator`. Negative test (`Get-Process`) produced no match. → True positive, no FP.

### 4.2 T1053.005 - Scheduled Task (a false negative, caught)
- **Behaviour:** persistence / privilege escalation via `schtasks /create`, often launching a scripting host.
- **Attack:** `Invoke-AtomicTest T1053.005 -TestNumbers 1` created `T1053_005_OnLogon` + `T1053_005_OnStartup`, each running `cmd.exe /c calc.exe`.
- **The catch:** the rule's suspicious-terms list contained `cmd /c`, but the atomic uses `cmd.exe /c`. Reading the rule against the actual command line *before* running showed it would return **0 events against its own test** - a false negative. Added `cmd.exe`; the detection then returned **2 events**, and that single added term was the only match.
- **Lesson:** validate rules against the *exact* attack string, not an approximation.

### 4.3 T1003.001 - LSASS Credential Access (prevention & telemetry)
- **Behaviour:** dumping LSASS memory to extract credentials (Mimikatz, `comsvcs.dll` MiniDump, ProcDump).
- **Telemetry gap:** Sysmon logged no ProcessAccess (EID 10) - the SwiftOnSecurity config ships it disabled - so LSASS access was invisible. Fixed by adding a `ProcessAccess` include for `lsass.exe` to `sysmonconfig-export.xml` and reloading.
- **Prevention:** on this hardened host the `comsvcs.dll MiniDump` command was **blocked at process launch by Attack Surface Reduction** - even with Defender real-time protection off - and LSA Protection (PPL) hardens LSASS further. The attack never reached LSASS, so no EID 10 was generated.
- **Finding:** *prevention eliminated the telemetry the detection relies on.* Documented as a **defense-in-depth win**; LSASS coverage must be paired with prevention/block events (Defender 1121/1122, ASR audit), not endpoint access logs alone.

## 5. Tuning notes

- **False negative (T1053.005):** `cmd /c` → `cmd.exe` (Sigma + SPL). 0 → 2 events.
- **Field mapping (T1136.001 / T1110):** the classic WinEventLog Security channel exposes `Account_Name` / `Source_Network_Address`, not `TargetUserName`. SPL adapted; Sigma kept canonical.
- **Telemetry (T1003.001):** enabled Sysmon ProcessAccess (EID 10).
- **Benign baseline:** ~4 min of normal activity (process/service queries, Notepad/Calc, ipconfig, gpupdate) → **0 false positives** across the rule set.

## 6. Lessons learned

- A rule that doesn't fire on its own atomic test is worse than no rule.
- Prevention can erase detection telemetry - pair endpoint detection with prevention/block monitoring.
- One Sigma source scales to multiple SIEMs, but field names differ by log format; adapt at the query layer, keep Sigma canonical.
- Telemetry gaps are silent failures - confirm the data source actually sees the behaviour before trusting the rule.

## 7. Appendix

- Rules: [`../rules/`](../rules/) · Searches: [`../spl/detections.spl`](../spl/detections.spl), [`../kql/detections.kql`](../kql/detections.kql)
- Coverage: [`../coverage-matrix.md`](../coverage-matrix.md)
- Full lab log + evidence: [`../lab/`](../lab/lab-journal.md)
- Reproduce from scratch: [`../RUNBOOK.md`](../RUNBOOK.md)
