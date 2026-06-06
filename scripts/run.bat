@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "ROOT=%%~fI"

pushd "%ROOT%" >nul

call "%SCRIPT_DIR%portable\bootstrap.bat"
if errorlevel 1 (
    echo [PORTABLE] ERROR: bootstrap fallido.
    popd >nul
    exit /b 1
)

echo [PORTABLE] Ejecutando auditoria con python_portable...
python_portable\python.exe main.py %*
set "EC=%ERRORLEVEL%"

popd >nul
exit /b %EC%
