@echo off
rem NetMapperPro web app on BBB. Started at boot by the NMPro scheduled task
rem (S4U: runs whether or not anyone is logged on). Serves 127.0.0.1:7890 only;
rem the Cloudflare tunnel publishes it as https://nmpro.timcase.ca.

rem Fail closed: without the Cloudflare Access settings the app would run with
rem no login check, so refuse to start instead.
if not exist A:\NetMapperPro\access_env.bat (
  echo %date% %time% access_env.bat missing: not starting without Cloudflare Access settings>> A:\NetMapperPro\server.log
  exit /b 1
)
call A:\NetMapperPro\access_env.bat

set PYTHONIOENCODING=utf-8
cd /d A:\NetMapperPro\web
A:\NetMapperPro\.venv\Scripts\python.exe A:\NetMapperPro\web\serve.py >> A:\NetMapperPro\server.log 2>&1
