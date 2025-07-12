@echo off
REM CyberNox Windows Installation Script
REM This script helps set up CyberNox on Windows systems

echo ================================
echo CyberNox Windows Setup Script
echo ================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://python.org
    pause
    exit /b 1
)

python --version
echo Python found!
echo.

echo Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: Failed to install Python dependencies
    echo Please check your internet connection and try again
    pause
    exit /b 1
)
echo Dependencies installed successfully!
echo.

echo Testing CyberNox installation...
python test_cybernox.py
if %errorlevel% neq 0 (
    echo WARNING: Some tests failed, but CyberNox should still work
    echo Check the output above for details
) else (
    echo All tests passed!
)
echo.

echo ================================
echo Setup Information
echo ================================
echo.
echo CyberNox is now installed and ready to use!
echo.
echo For FULL functionality (including packet capture):
echo   1. Download and install Npcap from: https://nmap.org/npcap/
echo   2. During installation, enable "WinPcap API compatibility mode"
echo   3. Restart your computer
echo   4. Run some commands as Administrator for network operations
echo.
echo Basic usage examples:
echo   python main.py --help
echo   python main.py recon --whois example.com
echo   python main.py scan --target 192.168.1.1 --ports 80 443
echo   python main.py shell --type bash --lhost 192.168.1.100 --lport 4444
echo.
echo For more examples, see README.md
echo.
pause
