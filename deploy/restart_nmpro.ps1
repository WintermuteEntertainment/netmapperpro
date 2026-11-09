# Restart the NetMapperPro web app on BBB and confirm it answers.
# Run on BBB (deploy_bbb.ps1 -Restart calls it over ssh).

$root = 'A:\NetMapperPro'
schtasks /End /TN NMPro 2>&1 | Out-Null
# /End does not always stop the child python, so stop it by its command line.
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
  Where-Object { $_.CommandLine -like '*NetMapperPro\web\serve.py*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 2
schtasks /Run /TN NMPro | Out-Null

for ($i = 0; $i -lt 15; $i++) {
  Start-Sleep -Seconds 2
  try {
    $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 http://127.0.0.1:7890/healthz
    if ($r.StatusCode -eq 200) { Write-Output "NMPro is up (healthz 200)"; exit 0 }
  } catch { }
}
Write-Output "NMPro did not answer within 30 s. Last lines of server.log:"
Get-Content "$root\server.log" -Tail 15 -ErrorAction SilentlyContinue
exit 1
