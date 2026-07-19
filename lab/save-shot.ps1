<#
  save-shot.ps1 - save the current CLIPBOARD image into the right lab phase folder.

  Run this ON THE HOST (where the project folder lives), right after you snip
  a screenshot to the clipboard (Win+Shift+S / PrtScn / Alt+PrtScn).

  Examples:
    .\save-shot.ps1 -Phase A -Name prereq-1-sysmon-events
    .\save-shot.ps1 -Phase B -Name T1547.001-detection-fired

  Phase:  A = prerequisites   B = detections   C = tuning   D = alerts
#>
param(
  [Parameter(Mandatory=$true)][ValidateSet('A','B','C','D')][string]$Phase,
  [Parameter(Mandatory=$true)][string]$Name
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$img = [System.Windows.Forms.Clipboard]::GetImage()
if ($null -eq $img) {
  Write-Host "No image on the clipboard. Snip first (Win+Shift+S), then re-run." -ForegroundColor Yellow
  return
}

$folders = @{ 'A'='phase-A-prerequisites'; 'B'='phase-B-detections'; 'C'='phase-C-tuning'; 'D'='phase-D-alerts' }
$dir = Join-Path $PSScriptRoot $folders[$Phase]
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

if (-not $Name.ToLower().EndsWith('.png')) { $Name = "$Name.png" }
$dest = Join-Path $dir $Name

$img.Save($dest, [System.Drawing.Imaging.ImageFormat]::Png)
$img.Dispose()
Write-Host "Saved -> $dest" -ForegroundColor Green
