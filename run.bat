@echo off
echo.
echo  ==========================================
echo   LicenseHub v2.1 - Server + Worker
echo  ==========================================
echo.

call venv\Scripts\activate.bat

if not exist .env (
    echo [LOI] Khong tim thay file .env!
    echo Hay copy .env.example thanh .env va dien thong tin vao.
    pause
    exit /b 1
)

echo [OK] Khoi dong Worker tu dong nhac hoa don qua han...
start "LicenseHub-Worker" /min cmd /c "call venv\Scripts\activate.bat && python worker.py"

echo [OK] Server dang chay tai http://localhost:8000
echo Nhan Ctrl+C de dung.
echo.

uvicorn main:app --reload --host 0.0.0.0 --port 8000
