@echo off
REM MedVault-PQ: one command to bring the whole demo up.
REM
REM   start.cmd              in-process ledger (no chain needed)
REM   start.cmd --with-chain also starts a local Hardhat chain on 127.0.0.1:8545
REM
REM Backend  http://127.0.0.1:8000   (FastAPI, docs at /docs)
REM Frontend http://localhost:5173   (Vite, proxies /api to the backend)

setlocal
set ROOT=%~dp0
set DISABLE_TELEMETRY=1

if /I "%~1"=="--with-chain" (
  echo [start] local Hardhat chain on 127.0.0.1:8545
  start "medvault-chain" cmd /c "cd /d "%ROOT%contracts" && set HARDHAT_DISABLE_TELEMETRY_PROMPT=true && npm run node"
  timeout /t 6 /nobreak >nul
)

echo [start] backend  http://127.0.0.1:8000
start "medvault-backend" cmd /c "cd /d "%ROOT%backend" && python -m uvicorn api:app --port 8000 --host 127.0.0.1"

timeout /t 3 /nobreak >nul

echo [start] frontend http://localhost:5173
start "medvault-frontend" cmd /c "cd /d "%ROOT%frontend" && npm run dev"

echo.
echo [start] open http://localhost:5173 - the MedVault group is the first tab group.
echo [start] to measure gas, use --with-chain and then choose the local chain ledger in the Demo tab.
endlocal
