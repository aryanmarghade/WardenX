@echo off
echo ===================================================
echo        WardenX EDR - Windows Installation
echo ===================================================
echo.

echo [1/3] Creating virtual environment (venv)...
python -m venv venv
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create virtual environment. Ensure Python is installed and added to PATH.
    pause
    exit /b %errorlevel%
)

echo.
echo [2/3] Installing dependencies from requirements.txt...
venv\Scripts\pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Dependency installation encountered issues.
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Installing WardenX package...
venv\Scripts\python setup.py install

echo.
echo ===================================================
echo        Installation Completed Successfully!
echo ===================================================
echo.
echo To launch the WardenX Security Center GUI Dashboard:
echo     venv\Scripts\python gui_app.py
echo.
echo To run CLI commands:
echo     venv\Scripts\wardenx --help
echo.
pause
