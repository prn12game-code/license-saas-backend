@echo off
echo Starting LicenseHub...
echo.

REM Activate the virtual environment
call venv\Scripts\activate.bat

REM Check if .env exists
if not exist .env (
    echo ERROR: .env file not found!
    echo Please copy .env.example to .env and fill in your values.
    pause
    exit /b 1
)

REM Start the server
echo Server starting at http://localhost:8000
echo Press Ctrl+C to stop.
echo.
uvicorn main:app --reload --host 0.0.0.0 --port 8000
