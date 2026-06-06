@echo off
REM run_tests.bat — Ejecutar tests automáticos del Worker Digital Rights Agent
echo.
echo ============================================================
echo  Worker Digital Rights Agent — Tests Automaticos
echo ============================================================
echo.

REM Detectar Python portátil o venv
IF EXIST "python_portable\python.exe" (
    SET PYTHON=python_portable\python.exe
    echo Preparando entorno portable...
    call scripts\portable\bootstrap.bat
    IF ERRORLEVEL 1 (
        echo.
        echo ERROR: No se pudo preparar python_portable.
        pause
        exit /b 1
    )
) ELSE IF EXIST ".venv\Scripts\python.exe" (
    SET PYTHON=.venv\Scripts\python.exe
) ELSE (
    SET PYTHON=python
)

echo Usando Python: %PYTHON%
echo.

REM Ejecutar tests con cobertura básica
%PYTHON% -m pytest tests\ -v --tb=short 2>&1
IF ERRORLEVEL 1 (
    echo.
    echo pytest no disponible o fallo al arrancar con este interprete. Reintentando con unittest...
    %PYTHON% -m unittest discover -s tests -v 2>&1
)

echo.
echo Ejecutar con: %PYTHON% -m pytest tests\ -v
echo Para test especifico: %PYTHON% -m pytest tests\test_audit_engine.py -v
echo.
pause
