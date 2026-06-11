@echo off
setlocal

REM build_mini_console_exe.bat
REM Genera WorkDRAG_Mini.exe (sin consola) para uso portable en USB/nube.

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "ROOT=%%~fI"
pushd "%ROOT%" >nul

if not exist "python_portable\python.exe" (
    echo [BUILD] ERROR: falta python_portable\python.exe
    popd >nul
    exit /b 1
)

echo [BUILD] Preparando entorno portable...
call scripts\portable\bootstrap.bat
if errorlevel 1 (
    echo [BUILD] ERROR: bootstrap fallido.
    popd >nul
    exit /b 1
)

echo [BUILD] Verificando PyInstaller...
python_portable\python.exe -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [BUILD] Instalando PyInstaller...
    python_portable\python.exe -m pip install pyinstaller --disable-pip-version-check
    if errorlevel 1 (
        echo [BUILD] ERROR: no se pudo instalar PyInstaller.
        popd >nul
        exit /b 1
    )
)

echo [BUILD] Compilando WorkDRAG_Mini.exe...
python_portable\python.exe -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --name WorkDRAG_Mini ^
    --distpath "%ROOT%\release" ^
    --workpath "%ROOT%\build\pyinstaller" ^
    --specpath "%ROOT%\build\pyinstaller" ^
    "%ROOT%\mini_console.pyw"
if errorlevel 1 (
    echo [BUILD] ERROR: compilacion fallida.
    popd >nul
    exit /b 1
)

echo [BUILD] OK: %ROOT%\release\WorkDRAG_Mini.exe
echo [BUILD] Copia la carpeta completa del proyecto junto al EXE para modo portable.

popd >nul
exit /b 0
