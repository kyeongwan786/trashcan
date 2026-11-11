
@echo off
setlocal

cd /d "%~dp0"

set "PYTHON=py -3.10-32"

echo ========================================
echo TrashCan Windows x86 Diagnostic Build
echo ========================================

%PYTHON% -c "import struct,sys; print('Python:',sys.version); print('Bitness:',struct.calcsize('P')*8); sys.exit(0 if struct.calcsize('P')*8 == 32 else 1)"

if errorlevel 1 (
    echo [ERROR] Python 3.10 x86 not found.
    pause
    exit /b 1
)

%PYTHON% -m pip install --upgrade pip
if errorlevel 1 goto :error

%PYTHON% -m pip install ^
    PyInstaller ^
    PySide2 ^
    qt-material ^
    sympy ^
    psutil ^
    requests

if errorlevel 1 goto :error

if not exist "Untitled-1.py" goto :missing
if not exist "kait_extract.py" goto :missing
if not exist "common.py" goto :missing
if not exist "TrashCan_entry.py" goto :missing
if not exist "kait_debug_run.py" goto :missing
if not exist "assets\main.ui" goto :missing

%PYTHON% -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --name TrashCan ^
    --add-data "assets\main.ui;." ^
    --add-data "Untitled-1.py;." ^
    --collect-all qt_material ^
    TrashCan_entry.py

if errorlevel 1 goto :error

echo.
echo ========================================
echo Build complete!
echo %~dp0dist\TrashCan.exe
echo ========================================
echo.
pause
exit /b 0

:missing
echo [ERROR] Required source file missing.
pause
exit /b 1

:error
echo [ERROR] Build failed.
pause
exit /b 1
