@echo off
REM repro.cmd — the Windows entry point for the same command as repro.sh.
REM
REM   repro.cmd            (seed 42, full grids)
REM   repro.cmd 1234       (a different seed)
REM   repro.cmd 42 --fast  (smaller grids, for a quick check)
REM
REM Writes backend\results\repro.json. Both scripts call the same Python module,
REM so they cannot drift apart.
setlocal
cd /d "%~dp0backend"

set SEED=%1
if "%SEED%"=="" set SEED=42

python -m medvault.repro --seed %SEED% --output results/repro.json %2 %3 %4
exit /b %ERRORLEVEL%
