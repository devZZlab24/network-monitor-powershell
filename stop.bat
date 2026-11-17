@echo off
taskkill /F /FI "WINDOWTITLE eq Net Monitor*" >nul 2>&1
echo Monitor stopped.
pause
