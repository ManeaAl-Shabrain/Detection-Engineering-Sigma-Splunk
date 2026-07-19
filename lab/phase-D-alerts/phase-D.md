# Phase D - Alerts + Wrap-up

Turn the top 3 rules into scheduled Splunk alerts (Save As → Alert → every 5 min →
trigger when results > 0), then finish the deliverables.
Save alert screenshots **here**: `alert-<name>.png`.

- [x] **#1 Encoded PowerShell** → alert `T1059.001 - Encoded PowerShell` - ✅ **FIRED 16:55:05** → `alert-encoded-powershell-fired.png` (config: `alert-encoded-powershell.png`)
- [x] **#6 Delete Shadow Copies** → alert `T1490 - Delete Shadow Copies` → `alert-shadow-copies.png`
- [x] **#8 SMB Brute Force** → alert `T1110 - SMB Brute Force` → `alert-brute-force.png`
- _(skipped #3 LSASS as an alert - prevented in this env, so it won't fire to demo)_
- [x] [`../../coverage-matrix.md`](../../coverage-matrix.md) - 8/8 addressed (7 detected · 1 prevented)
- [x] Report drafted in [`../../report/`](../../report/Detection-Engineering-Report.md) - exported to `Detection-Engineering-Report.pdf` (+ styled `report.html`)
- [x] README **Results** + **What I learned** filled in

**Notes:**
-
