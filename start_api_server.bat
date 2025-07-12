@echo off
REM CyberNox API Server Startup Script
REM Quick launcher for the CyberNox API server

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                    CyberNox API Server                        ║
echo ║                      Quick Launcher                           ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

echo 🐍 Python detected
echo 🚀 Starting CyberNox API Server...
echo.

REM Start the API server
python start_api.py --host 127.0.0.1 --port 5000

pause
