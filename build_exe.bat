@echo off
rem Builds dist\SignupFixtureLab.exe from this checkout.
rem
rem Run this ON the Windows machine that will use the tool. PyInstaller is not a
rem cross-compiler: an .exe built on Linux or macOS will not run on Windows. It needs a
rem one-time "pip install pyinstaller" (the command below does it for you) and it writes
rem build\ and dist\ next to this file - both are disposable.
setlocal enableextensions
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (echo Python 3.11+ is required: www.python.org/downloads & pause & exit /b 1)

%PY% -m PyInstaller --version >nul 2>nul
if errorlevel 1 (
  echo installing pyinstaller into the current environment...
  %PY% -m pip install --disable-pip-version-check --user pyinstaller
  if errorlevel 1 (echo pip install pyinstaller failed & pause & exit /b 1)
)

echo building SignupFixtureLab.exe ...
%PY% -m PyInstaller --noconfirm --clean --onefile --console ^
  --name SignupFixtureLab ^
  --add-data "seeds\schema.sql;seeds" ^
  --collect-submodules console --collect-submodules seeds ^
  --collect-submodules load --collect-submodules mockapi --collect-submodules abuse ^
  console\__main__.py
if errorlevel 1 (echo build failed & pause & exit /b 1)

echo.
echo Built  dist\SignupFixtureLab.exe
echo   Copy that one file wherever you want to work. It works from its own folder: var\ is
echo   written next to the .exe even when a shortcut starts it from somewhere else, so keep it
echo   somewhere you can write to (not Program Files). Double-clicking it starts the console,
echo   seeds the first accounts and opens http://127.0.0.1:8010/.
echo   Stop it with Ctrl-C in the window it opens, or by closing that window.
pause
endlocal
