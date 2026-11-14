@echo off
REM Creates PasswordManager shortcuts with the app icon:
REM   - Start Menu, with the hotkey Ctrl+Alt+P
REM   - Desktop
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
  "$sh = New-Object -ComObject WScript.Shell;" ^
  "$desk = [Environment]::GetFolderPath('Desktop') + '\PasswordManager.lnk';" ^
  "foreach ($p in @($env:LNK, $desk)) {" ^
  "  $s = $sh.CreateShortcut($p);" ^
  "  $s.TargetPath = $env:TARGET; $s.WorkingDirectory = $env:ROOT;" ^
  "  $s.IconLocation = $env:ROOT + '\assets\icon.ico'; $s.Description = 'PasswordManager';" ^
  "  if ($p -eq $env:LNK) { $s.Hotkey = 'CTRL+ALT+P' };" ^
  "  $s.Save(); Write-Host ('Created: ' + $p) }"
if errorlevel 1 exit /b 1
echo.
echo Target : %TARGET%
echo Press Ctrl+Alt+P to open PasswordManager, double-click the Desktop icon, or search for it in Start.
echo If an old icon still shows, run:  ie4uinit.exe -show
