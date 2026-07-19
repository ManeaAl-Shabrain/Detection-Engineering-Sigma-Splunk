# Detection Engineering Pack - Sigma → Splunk + KQL

> A threat-informed detection pack: **8 Sigma rules** mapped to MITRE ATT&CK,
> converted to **Splunk SPL** and **Microsoft KQL** from a single source, each
> validated against a real **Atomic Red Team** test and tuned to cut false positives.

**Category:** 🛡️ Blue Team / Detection Engineering · **Data sources:** Sysmon + Windows Security · **SIEM:** Splunk (KQL bonus for Sentinel/Defender)

---

## Why this exists

Real detection engineers don't write random rules - they run a repeatable lifecycle
against techniques attackers actually use ("threat-informed defense"):

```
1. DATA SOURCE     Which logs can even see this attack?      (Sysmon / Security)
2. DETECTION       Write the logic                            (Sigma  ->  SPL / KQL)
3. TEST & VALIDATE Run the real technique                     (Atomic Red Team)
4. TUNE            Kill false positives so analysts trust it
5. DEPLOY          Save as an alert + document coverage       (coverage matrix)
```

## What's covered

8 techniques across **6 ATT&CK tactics** - see the full [coverage matrix](coverage-matrix.md).

| # | Technique | ATT&CK | Tactic | Data source |
|---|-----------|--------|--------|-------------|
| 1 | Encoded PowerShell | T1059.001 | Execution | Sysmon EID 1 |
| 2 | Registry Run-Key persistence | T1547.001 | Persistence | Sysmon EID 13 |
| 3 | LSASS credential access | T1003.001 | Credential Access | Sysmon EID 10 |
| 4 | Scheduled task creation | T1053.005 | Persistence / PrivEsc | Sysmon EID 1 |
| 5 | Create local account | T1136.001 | Persistence | Security 4720 |
| 6 | Delete volume shadow copies | T1490 | Impact | Sysmon EID 1 |
| 7 | LOLBin abuse (certutil/regsvr32/rundll32) | T1218 | Defense Evasion | Sysmon EID 1 |
| 8 | SMB / RDP brute force | T1110 | Credential Access | Security 4625 |

## Repository layout

```
Detection-Engineering-Sigma-Splunk/
|- README.md              you are here
|- RUNBOOK.md             the lab loop: install ART, test each rule, tune, alert
|- coverage-matrix.md     technique -> rule -> test -> detected -> tuning
|- rules/                 8 Sigma .yml source rules (the deliverable)
|- spl/detections.spl     Splunk searches (converted from rules/)
|- kql/detections.kql     Sentinel/Defender KQL (bonus, converted from rules/)
|- report/                write-up -> export to PDF
'- lab/                    YOUR working area (all execution work lands here)
   |- lab-journal.md       index of the whole run
   |- phase-A-prerequisites/   data source + fields + ART install (+ screenshots)
   |- phase-B-detections/      each detection firing (+ screenshots)
   |- phase-C-tuning/          false-positive tuning (+ before/after shots)
   |- phase-D-alerts/          saved alerts (+ screenshots)
   '- exports/                 raw Splunk exports, .conf snippets
```

## Sigma is the source of truth

Rules are authored once in vendor-neutral [Sigma](https://sigmahq.io/), then
converted to each SIEM's query language with the official CLI:

```bash
pip install sigma-cli
sigma plugin install splunk
sigma plugin install microsoft365defender

sigma convert -t splunk rules/                 # -> Splunk SPL
sigma convert -t kusto  rules/                 # -> Microsoft KQL
sigma convert -t splunk rules/T1059.001_encoded_powershell.yml   # single rule
```

The committed `spl/detections.spl` and `kql/detections.kql` are hand-verified
equivalents adapted to this lab's index/sourcetype naming.

## Validate it (the part that makes it real)

A detection you never tested is a guess. Every rule is proven against its
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test - see
**[RUNBOOK.md](RUNBOOK.md)** for the full per-technique loop, then record results
in the [coverage matrix](coverage-matrix.md).

> ⚠️ **Lab only.** Some tests dump LSASS or delete shadow copies. Snapshot the VM
> first and run only inside an isolated host-only lab you own. Revert when done.

## Results

- **8/8 techniques addressed across 6 ATT&CK tactics - 7 detected, 1 prevented.** See [coverage-matrix.md](coverage-matrix.md).
- **Validated against real attacks:** every rule was tested with Atomic Red Team (or an equivalent live technique) on an isolated Splunk + Sysmon lab; each technique's attack + fired-search evidence is in [`lab/phase-B-detections/`](lab/phase-B-detections/).
- **Tuning wins (the interesting part):**
  - Caught a **false negative** in the scheduled-task rule - the atomic uses `cmd.exe /c` but the rule only matched `cmd /c`, so it would have missed its own test.
  - Fixed **field-name mapping** for the Security-log rules (`Account_Name` / `Source_Network_Address` in classic WinEventLog vs the canonical Sigma schema).
  - Closed a **telemetry gap** - Sysmon wasn't logging ProcessAccess (EID 10), so LSASS access was invisible until the config was fixed.
- **Defense-in-depth finding:** LSASS dumping (T1003.001) was **prevented** on the hardened host (ASR + LSA Protection) *before* it could generate telemetry - detection must be paired with prevention/block-event monitoring.
- **Benign baseline:** 0 false positives on ~4 min of normal activity → rules confirmed deployable.
- **Deployed:** top 3 rules as scheduled Splunk alerts; the Encoded-PowerShell alert is confirmed firing.
- **Full evidence** is organized by phase in [`lab/`](lab/lab-journal.md) (prerequisites → detections → tuning → alerts).

## What I learned

- **A rule that doesn't fire on its own atomic test is worse than no rule.** Reading each rule against the *exact* attack command line - not "close enough" - caught a false negative I'd otherwise have shipped.
- **Prevention can erase detection telemetry.** On a hardened host, ASR / LSA Protection stopped the LSASS attack before Sysmon ever saw it - endpoint detections need prevention and block events as a complement, not a substitute.
- **One Sigma source, many SIEMs - but field names still bite.** The same technique surfaces different field names depending on log format; keeping Sigma canonical and adapting at the SPL/KQL layer is the workflow that actually scales.

---

Author: **Manea Al-Shabrain** · Part of the [Master Cybersecurity Portfolio](../docs/MasterCyberSecurityProjects.html) (Top-15 · Detection Engineering Platform)
