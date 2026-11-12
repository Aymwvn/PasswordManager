@echo off
REM Reproduce CI's Windows test cells locally: Python 3.10 and 3.12 (ruff + pytest).
REM Needs uv. From the activated project venv run once:  pip install uv
REM Writes the full output to a file on your Desktop; prints a short summary here.
setlocal
cd /d "%~dp0\.."
set "REPORT=%USERPROFILE%\Desktop\ci-local-report.txt"
set "BASE=%TEMP%\pm-ci-local"
where uv >nul 2>&1
if errorlevel 1 (
  echo uv was not found. Run:  pip install uv
  exit /b 1
)
echo CI local reproduction> "%REPORT%"
for %%V in (3.10 3.12) do call :cell %%V
echo.
echo ==== SUMMARY ^(full output: %REPORT%^) ====
findstr /R /C:"^=====" /C:"^FAILED" /C:"^ERROR" /C:"passed" /C:"failed" /C:"All checks passed" /C:"Found [0-9]* error" "%REPORT%"
exit /b 0

:cell
set "PYV=%~1"
set "ENVDIR=%BASE%\py%PYV%"
echo ===== Python %PYV% =====>> "%REPORT%"
if exist "%ENVDIR%" rmdir /s /q "%ENVDIR%"
echo [Python %PYV%] creating environment ^(downloads Python the first time^)...
uv venv --python %PYV% "%ENVDIR%" >> "%REPORT%" 2>&1
uv pip install --python "%ENVDIR%\Scripts\python.exe" -e ".[dev]" >> "%REPORT%" 2>&1
echo [Python %PYV%] ruff...
"%ENVDIR%\Scripts\python.exe" -m ruff check . >> "%REPORT%" 2>&1
echo [Python %PYV%] pytest...
"%ENVDIR%\Scripts\python.exe" -m pytest -q -p no:cacheprovider -ra >> "%REPORT%" 2>&1
goto :eof
