@echo off
REM Creates a Start Menu shortcut for PasswordManager with the hotkey Ctrl+Alt+P.
REM (Windows only allows Ctrl+Alt+<key> for shortcut hotkeys; for Win+Alt+P see docs\SHORTCUTS.md.)
setlocal
set "ROOT=%~dp0.."
for %%I in ("%ROOT%") do set "ROOT=%%~fI"
set "TARGET=%ROOT%\dist\PasswordManager\PasswordManager.exe"
if not exist "%TARGET%" set "TARGET=%ROOT%\.venv\Scripts\pm-app.exe"
if not exist "%TARGET%" (
  echo Could not find the app. Install it first:  pip install -e ".[app]"
  exit /b 1
)
set "LNK=%APPDATA%\Microsoft\Windows\Start Menu\Programs\PasswordManager.lnk"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK);" ^
  "$s.TargetPath = $env:TARGET; $s.WorkingDirectory = $env:ROOT;" ^
  "$s.IconLocation = $env:ROOT + '\assets\icon.ico'; $s.Hotkey = 'CTRL+ALT+P';" ^
  "$s.Description = 'PasswordManager'; $s.Save()"
if errorlevel 1 exit /b 1
echo.
echo Created: %LNK%
echo Target : %TARGET%
echo Press Ctrl+Alt+P to open PasswordManager, or find it by typing its name in the Start menu.
