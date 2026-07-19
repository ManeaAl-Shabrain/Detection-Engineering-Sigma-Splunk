# Lab Runbook - Validate & Tune the Detection Pack

This is the hands-on half of the project. The rules are written; here you **prove
each one fires against a real attack**, tune out false positives, and capture
evidence. Everything runs on your existing SOC lab (Splunk + Sysmon on WIN11-01,
Kali attacker).

> ⚠️ **Snapshot WIN11-01 before you start.** Some atomic tests dump LSASS or delete
> shadow copies - harmless in an isolated lab, but revert the snapshot when done.
> Never run these on a machine you don't own or on a networked/production host.

---

## Step 0 - Prerequisite checks

**A. Confirm Sysmon logs still reach Splunk:**

```spl
index=main source="*Sysmon/Operational" EventCode=1 | head 5
```

Process-creation events → ready. Nothing → restart `SplunkForwarder` on WIN11-01 first.

**B. Confirm clean parsed fields** (needs the *Splunk Add-on for Sysmon*: Apps →
Find More Apps → search "Sysmon"):

```spl
index=main source="*Sysmon/Operational" EventCode=1
| table _time host Image CommandLine ParentImage
```

`Image` and `CommandLine` show real values (not blank) → fields are good. Sigma
references these exact field names.

## Step 1 - Install the validator (Atomic Red Team)

On WIN11-01, **PowerShell as Administrator**:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
Install-AtomicRedTeam -getAtomics -Force
Import-Module invoke-atomicredteam
```

Preview a test without running it (proves the runner works):

```powershell
Invoke-AtomicTest T1059.001 -ShowDetails
```

---

## Step 2 - The detection loop (repeat per technique)

For each of the 8 techniques:

1. **Test** - run the atomic (table below).
2. **Detect** - run the matching query from [`spl/detections.spl`](spl/detections.spl).
   You should see the test event → ✅ true positive.
3. **Check FP** - run benign activity (see Step 3) and confirm the query does **not**
   alert on it. If it does, tighten the rule and re-convert.
4. **Record** - flip the row in [`coverage-matrix.md`](coverage-matrix.md) to ✅.
5. **Screenshot** - capture the detection firing → `lab/phase-B-detections/<ID>-detection-fired.png`.

### Worked example - T1059.001 (Encoded PowerShell)

```powershell
Invoke-AtomicTest T1059.001
```

Then run detection [1] from `spl/detections.spl`. Your encoded-command event appears
(`Image=*\powershell.exe`, `CommandLine=* -enc *`). Now run a normal command
(`Get-Process`) and confirm **no** alert. Screenshot → `T1059.001-detection-fired.png`.

### All 8 - atomic test → detection

| # | ATT&CK | Atomic test | Detection to run |
|---|--------|-------------|------------------|
| 1 | T1059.001 | `Invoke-AtomicTest T1059.001` | spl [1] |
| 2 | T1547.001 | `Invoke-AtomicTest T1547.001` | spl [2] |
| 3 | T1003.001 | `Invoke-AtomicTest T1003.001` | spl [3] |
| 4 | T1053.005 | `Invoke-AtomicTest T1053.005` | spl [4] |
| 5 | T1136.001 | `Invoke-AtomicTest T1136.001` | spl [5] |
| 6 | T1490 | `Invoke-AtomicTest T1490` | spl [6] |
| 7 | T1218.011 | `Invoke-AtomicTest T1218.011` | spl [7] |
| 8 | T1110 | reuse the SOC-lab NetExec/Hydra SMB attack from Kali | spl [8] |

> After LSASS (T1003.001) and shadow-copy (T1490) tests, run
> `Invoke-AtomicTest <ID> -Cleanup` and consider reverting the snapshot.

---

## Step 3 - Tune against a benign baseline (the part that matters)

Generate ~15 minutes of normal activity: open apps, browse, run everyday PowerShell
(`Get-Process`, `Get-Service`), install something small, let a scheduled task run.
Re-run all 8 detections. **Anything that alerts on this benign activity is a false
positive** - fix it and re-convert:

- **#1 Encoded PS:** ` -e ` is broad; if noisy, drop it and keep `-enc` / `-encodedcommand` / `-ec`.
- **#3 LSASS:** add your EDR/AV `SourceImage` to the `filter_system` exclusion.
- **#4 Scheduled task:** the `suspicious` block already scopes to user-writable paths / script hosts.
- **#7 LOLBins:** if certutil is noisy, add a `ParentImage` scope (Office / script hosts).

Document **what you tuned and why** - that narrative is what separates an engineer
from a beginner, and it's the strongest interview material in the whole project.

## Step 4 - Turn the top 3 into Splunk alerts

For your 3 highest-value rules (suggest #1, #3, #6): run the search → **Save As →
Alert** → schedule every 5 min → trigger when *number of results > 0*. Screenshot one
firing → `lab/phase-D-alerts/alert-encoded-powershell.png`.

## Step 5 - Evidence

Every ✅ in the matrix should have a matching screenshot in its `lab/phase-*/` folder. Then
fill in the **Results** section of [README.md](README.md) and the report in
[`report/`](report/Detection-Engineering-Report.md).
