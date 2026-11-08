@echo off
chcp 65001 > nul
cd /d "%~dp0"
echo.
echo  Network Peek -> http://127.0.0.1:7890
echo.
python app.py
pause
