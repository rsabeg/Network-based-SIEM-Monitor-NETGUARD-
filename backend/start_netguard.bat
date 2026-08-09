@echo off
REM NETGUARD - one-click backend + dashboard launcher
REM Just double-click this file. No typing required.

echo Starting NETGUARD backend...
cd /d "%~dp0"

start "NETGUARD Backend" cmd /k "npm start"

echo Waiting a moment for the server to boot...
timeout /t 3 /nobreak >nul

echo Opening dashboard in your browser...
start http://localhost:8000

echo.
echo Done. Backend is running in the other window - do not close it during your demo.
pause
