@echo off
rem Signup fixture lab - double-click launcher. Needs Python 3.11+ on PATH, nothing else:
rem no install step, no admin rights, no outbound network. Any arguments you add are passed
rem through, e.g.  run.bat --port 8090
setlocal enableextensions
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY where python3 >nul 2>nul && set "PY=python3"
if not defined PY goto :nopython

%PY% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" 2>nul
if errorlevel 1 goto :oldpython

if not exist "console\server.py" goto :wrongdir

echo starting the signup fixture console (Generator Mode / Operational Mode / Settings)
echo   page:    http://127.0.0.1:8010/
echo   fixture: var\test.db     account list: var\accounts.txt
echo   first run seeds a few accounts so the tabs open with something in them
echo   Ctrl-C, or closing this window, stops the server. The fixture stays on disk.
echo.
%PY% -m console --bootstrap --open-browser %*
goto :end

:nopython
echo Python 3.11 or newer is required and none was found on PATH.
echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
pause
goto :end

:oldpython
echo This tool needs Python 3.11+; the interpreter on PATH is older than that.
pause
goto :end

:wrongdir
echo Put this file in the repo folder and run it from there: it expects console\server.py
echo to sit next to it (that is where the tooling lives).
pause
goto :end

:end
endlocal
