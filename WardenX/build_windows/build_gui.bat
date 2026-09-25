@echo off
echo ===================================================
echo      WardenX GUI - Windows Build Script
echo ===================================================
echo.

:: Ensure we are running from project root
cd /d "%~dp0\.."

echo [1/3] Installing/verifying build dependencies...
pip install pyinstaller customtkinter

echo.
echo [2/3] Building standalone WardenX_UI executable...
pyinstaller --name WardenX_UI --onefile --windowed --collect-all customtkinter --add-data "rules/malware.yar;rules" gui_app.py

if %errorlevel% neq 0 (
    echo [ERROR] PyInstaller build failed.
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Moving binary to build_windows directory...
if not exist "build_windows" mkdir "build_windows"
powershell -Command "Get-Process -Name WardenX_UI -ErrorAction SilentlyContinue | Stop-Process -Force; Copy-Item -Force dist\WardenX_UI.exe build_windows\WardenX_UI.exe"
if exist "build_windows\WardenX_UI.exe" (
    echo [SUCCESS] Binary created at build_windows\WardenX_UI.exe
) else (
    echo [ERROR] build_windows\WardenX_UI.exe not found.
    exit /b 1
)

echo.
echo ===================================================
echo   Build Successful: build_windows\WardenX_UI.exe
echo ===================================================
