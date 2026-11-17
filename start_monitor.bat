@echo off
cd /d "%~dp0"
title Net Monitor
:loop
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0net_monitor.ps1"
timeout /t 2 >nul
goto loop
