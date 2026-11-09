# One-time setup on BBB, run there after the first deploy. Safe to re-run.
#
#   1. Creates an isolated Python environment at A:\NetMapperPro\.venv from
#      BBB's Python 3.12, so nothing installed here touches Jazz or anything
#      else on the machine.
#   2. Installs web\requirements.txt into it and records exact versions.
#   3. Registers the NMPro scheduled task (copied from ComputeForHope: starts
#      45 s after boot, runs logged off, never times out). It does not start it.
#
# Starting the app also needs A:\NetMapperPro\access_env.bat (see
# docs/DEPLOY_BBB.md); start_nmpro.bat refuses to run without it.

$ErrorActionPreference = 'Stop'
$root = 'A:\NetMapperPro'
$basePython = 'C:\Users\twwca\AppData\Local\Programs\Python\Python312\python.exe'
$venvPython = "$root\.venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) {
  Write-Output "Creating virtual environment $root\.venv from $basePython"
  & $basePython -m venv "$root\.venv"
  if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
} else {
  Write-Output "Virtual environment already exists"
}

Write-Output "Installing $root\web\requirements.txt into the venv"
& $venvPython -m pip install --disable-pip-version-check -r "$root\web\requirements.txt"
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }
& $venvPython -m pip freeze | Out-File -Encoding ascii "$root\pip-freeze.txt"
Write-Output "Installed:"
Get-Content "$root\pip-freeze.txt"

if (Get-ScheduledTask -TaskName NMPro -ErrorAction SilentlyContinue) {
  Write-Output "Task NMPro already registered"
} else {
  $action = New-ScheduledTaskAction -Execute "$root\deploy\start_nmpro.bat"
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $trigger.Delay = 'PT45S'
  $principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\twwca" -LogonType S4U
  $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName NMPro -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings `
    -Description 'NetMapperPro web app on 127.0.0.1:7890 (nmpro.timcase.ca)' | Out-Null
  Write-Output "Registered task NMPro (not started)"
}
