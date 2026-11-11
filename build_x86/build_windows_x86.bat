@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=py -3.10-32"

%PYTHON% -c "import struct,sys; print('Python:',sys.version); print('Bitness:',struct.calcsize('P')*8); sys.exit(0 if struct.calcsize('P')*8 == 32 else 1)"
if errorlevel 1 (
    echo [ERROR] 32-bit Python 3.10 was not found or is not 32-bit.
    echo Install Python 3.10 x86, then run this file again.
    pause
    exit /b 1
)

%PYTHON% -m pip install --upgrade pip
if errorlevel 1 goto :error

%PYTHON% -m pip install PyInstaller PySide2 qt-material sympy psutil requests
if errorlevel 1 goto :error

%PYTHON% -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name TrashCan ^
    --add-data "assets\main.ui;." ^
    --collect-all qt_material ^
    Untitled-1.py
if errorlevel 1 goto :error

echo.
echo Build complete: %~dp0dist\TrashCan.exe
pause
exit /b 0

:error
echo.
echo [ERROR] Build failed. See the error above.
pause
exit /b 1
