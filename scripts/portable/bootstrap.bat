@echo off
setlocal

REM Bootstrap modular para ejecutar el proyecto con python_portable
set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..\..") do set "ROOT=%%~fI"

pushd "%ROOT%" >nul

set "PYTHON=python_portable\python.exe"
if not exist "%PYTHON%" (
    echo [PORTABLE] ERROR: No se encontro %PYTHON%
    popd >nul
    exit /b 1
)

set "GETPIP_TMP=%TEMP%\workdrag_get_pip.py"

echo [PORTABLE] Verificando pip...
%PYTHON% -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [PORTABLE] pip no disponible. Descargando get-pip.py...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing https://bootstrap.pypa.io/get-pip.py -OutFile '%GETPIP_TMP%'"
    if errorlevel 1 (
        echo [PORTABLE] ERROR: No se pudo descargar get-pip.py
        popd >nul
        exit /b 1
    )

    echo [PORTABLE] Instalando pip en python_portable...
    %PYTHON% "%GETPIP_TMP%" --no-warn-script-location --disable-pip-version-check
    if errorlevel 1 (
        del /q "%GETPIP_TMP%" >nul 2>&1
        echo [PORTABLE] ERROR: No se pudo instalar pip
        popd >nul
        exit /b 1
    )
    del /q "%GETPIP_TMP%" >nul 2>&1
)

echo [PORTABLE] Verificando dependencias del proyecto...
set "MISSING="
%PYTHON% -c "import importlib.util;mods=['psutil','rich','reportlab','flask'];missing=[m for m in mods if importlib.util.find_spec(m) is None];print(','.join(missing))" > "%TEMP%\portable_missing_modules.txt" 2>nul
set /p MISSING=<"%TEMP%\portable_missing_modules.txt"

if defined MISSING (
    echo [PORTABLE] Faltan modulos: %MISSING%
    echo [PORTABLE] Instalando requirements.txt...
    %PYTHON% -m pip install -r requirements.txt --disable-pip-version-check
    if errorlevel 1 (
        echo [PORTABLE] ERROR: Fallo instalando requirements.txt
        popd >nul
        exit /b 1
    )
) else (
    echo [PORTABLE] Dependencias OK.
)

del /q "%TEMP%\portable_missing_modules.txt" >nul 2>&1

popd >nul
exit /b 0
