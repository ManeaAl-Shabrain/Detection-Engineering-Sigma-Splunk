# Phase C - Tuning

A rule isn't done when it fires once - it's done when it catches the attack **and**
stays quiet on normal activity. This phase records the rule fixes made during
validation and the benign-baseline false-positive check.

## Rule adjustments made during validation

| Rule | Issue found | Change | Result | Date |
|------|-------------|--------|--------|------|
| T1053.005 Scheduled task | Atomic uses `cmd.exe /c`; rule only had `cmd /c` → **0 events against its own test** (false negative) | Added `cmd.exe` to the suspicious command-line terms (Sigma + SPL) | 0 → 2 events | 2026-07-18 |
| T1136.001 / T1110 (Security log) | Rule used `TargetUserName`; this lab's Security channel is classic WinEventLog → field is `Account_Name` / `Source_Network_Address` | Adapted SPL [5] and [8]; Sigma keeps the canonical schema (converter's job) | Both fired correctly | 2026-07-18 |
| T1003.001 LSASS | Sysmon wasn't logging ProcessAccess (EID 10) at all - a telemetry gap | Added a `ProcessAccess` include for `lsass.exe` to `sysmonconfig-export.xml` + reloaded | EID 10 logging enabled | 2026-07-18 |

## Benign baseline (false-positive check)

**Activity generated (WIN11-01, ~4 min, no attacks):** repeated `Get-Process` /
`Get-Service` / `Get-ChildItem` / `Get-CimInstance`, opened & closed Notepad and Calc,
`ipconfig /all`, `systeminfo`, `gpupdate /target:computer`.

**Result:** the consolidated EID-1 false-positive check (T1059.001 / T1053.005 / T1218)
returned **0 events**. The Security-log and registry rules (4720 / 4625 / run-key) are
inherently rare and did not fire. → **No false positives; all rules confirmed deployable.**

Evidence: `tuning-benign-baseline-clean.png` (+ `tuning-benign-activity.png`)

## Summary - what I tuned and why

- The most valuable fixes were **false negatives** - rules missing their *own* attack -
  caught by reading each rule against the exact atomic command line (`cmd /c` vs
  `cmd.exe /c`). A rule that doesn't fire on its own test is worse than no rule.
- **Field-name mapping** matters: the same technique yields different Splunk field names
  by log format (XmlWinEventLog vs classic WinEventLog). Sigma stays canonical; the SPL
  layer adapts.
- **Telemetry gaps are invisible failures:** T1003.001's rule was fine, but the data
  source wasn't logging - no logs, no detection.
- The benign baseline proved the rules are specific enough to deploy without noise.
