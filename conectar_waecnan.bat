@echo off
echo === Waecnan Server Setup ===
echo.

REM Verifica se plink existe
if not exist "%~dp0plink.exe" (
    echo Baixando plink...
    powershell -Command "Invoke-WebRequest -Uri 'https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe' -OutFile '%~dp0plink.exe'"
)

echo Conectando ao servidor...
echo.
"%~dp0plink.exe" -ssh root@157.173.106.62 -pw Waecnan2026 -no-antispoof

pause
