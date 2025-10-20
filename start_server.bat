@echo off
chcp 65001 >nul
echo.
echo =========================================
echo   WebSSH Server - Startup Script
echo =========================================
echo.

REM Check if Rust is installed
where cargo >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: Rust/Cargo is not installed
    echo Please install Rust from https://rustup.rs/
    pause
    exit /b 1
)

echo [OK] Rust/Cargo found
echo.

REM Build the project
echo Building project in release mode...
cargo build --release 2>&1 | powershell -Command "$input | Select-Object -Last 10"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed
    pause
    exit /b 1
)
echo [OK] Build successful
echo.

REM Create data directory if it doesn't exist
if not exist "data" (
    echo Creating data directory...
    mkdir data
    echo [OK] Data directory created
)

REM Start the server
echo.
echo Starting WebSSH server...
echo Server will be available at: http://127.0.0.1:18022
echo Default credentials: admin / admin
echo IMPORTANT: Change the default password after first login!
echo.
echo You will be prompted to enter the master password.
echo First time: Set a strong password
echo Subsequent: Use the same password
echo.

REM Run the server
target\release\webssh.exe

