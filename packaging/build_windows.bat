@echo off
REM Build dist\PasswordManager\PasswordManager.exe  (run from anywhere)
setlocal
cd /d "%~dp0\.."
pip install -e ".[app,build]" || exit /b 1
pyinstaller --noconfirm --clean --windowed --name PasswordManager ^
  --specpath build ^
  --icon "%CD%\assets\icon.ico" ^
  --paths "%CD%\src" ^
  --add-data "%CD%\src\passwordmanager\ui\static;passwordmanager\ui\static" ^
  --collect-submodules uvicorn ^
  --collect-all argon2 ^
  --collect-all _argon2_cffi_bindings ^
  "%CD%\packaging\launcher.py" || exit /b 1
echo.
echo Built: dist\PasswordManager\PasswordManager.exe
