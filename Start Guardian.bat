@echo off
title WiFi Admin Guardian

:: ── Relaunch as Administrator if not already elevated ──────────────
:: (the sniffer and the firewall rule both need admin rights)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator access...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: ── Run from the folder this file lives in ─────────────────────────
cd /d "%~dp0"

:: ── Open the dashboard in the default browser once the server is up
start "" /min cmd /c "timeout /t 4 /nobreak >nul & start "" http://127.0.0.1:5000"

:: ── Start the monitor (tries the py launcher, then python) ─────────
where py >nul 2>&1
if %errorlevel% equ 0 (
    py run.py
) else (
    python run.py
)

echo.
echo WiFi Admin Guardian stopped.
pause
