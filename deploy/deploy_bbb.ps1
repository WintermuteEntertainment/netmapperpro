# Push NetMapperPro to BBB (A:\NetMapperPro), served at https://nmpro.timcase.ca
#
#   powershell -File D:\Repos\netmapperpro\deploy\deploy_bbb.ps1 [-Restart]
#
# Deploys the COMMITTED code at HEAD (git archive), so uncommitted edits never
# reach the server. oui.csv is git-ignored and sent separately. Existing
# web\scans, .venv, access_env.bat and server.log on BBB are left alone.
#
# BBB is reached over Tailscale; its SSH lands in WSL bash, so Windows paths
# are /mnt/a/... and Windows commands go through powershell.exe. scp/sftp to
# BBB hang, so files are streamed through ssh. One ssh session at a time.

param([switch]$Restart)
$ErrorActionPreference = 'Stop'
$bbb = 'twwca@100.69.250.80'
$ps = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

if (git status --porcelain -- netmapper web deploy NET_MAPPER_PRO.py) {
  Write-Warning "Uncommitted changes exist; only the committed HEAD is deployed."
}

Write-Host "Packaging HEAD ($(git rev-parse --short HEAD)) ..."
git archive --format=tar.gz -o _push.tgz HEAD NET_MAPPER_PRO.py netmapper web deploy
if ($LASTEXITCODE -ne 0) { throw "git archive failed" }

Write-Host "Copying code to BBB ..."
cmd /c "ssh -o BatchMode=yes $bbb ""mkdir -p /mnt/a/NetMapperPro && cat > /mnt/a/NetMapperPro/_push.tgz && cd /mnt/a/NetMapperPro && tar -xzf _push.tgz && rm _push.tgz"" < _push.tgz"
if ($LASTEXITCODE -ne 0) { throw "copy to BBB failed" }
Remove-Item _push.tgz -ErrorAction SilentlyContinue

if (Test-Path oui.csv) {
  Write-Host "Copying oui.csv ..."
  cmd /c "ssh -o BatchMode=yes $bbb ""cat > /mnt/a/NetMapperPro/oui.csv"" < oui.csv"
  if ($LASTEXITCODE -ne 0) { throw "oui.csv copy failed" }
}

if ($Restart) {
  Write-Host "Restarting the NMPro task ..."
  ssh -o BatchMode=yes $bbb "$ps -File A:/NetMapperPro/deploy/restart_nmpro.ps1 < /dev/null"
}

Write-Host ""
Write-Host "Done. https://nmpro.timcase.ca" -ForegroundColor Green
