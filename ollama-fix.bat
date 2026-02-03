@echo off
echo ==========================================
echo    OLLAMA CUDA FIX / CPU MODE TOGGLE
echo ==========================================
echo.
echo This script helps resolve CUDA/GPU errors by forcing
echo Ollama into CPU mode or restarting the service.
echo.
echo [1] Restart Ollama in CPU-ONLY Mode (Avoids CUDA errors)
echo [2] Restart Ollama in DEFAULT Mode (Uses GPU if available)
echo [3] Check if Ollama is running
echo [4] Exit
echo.

set /p choice="Enter choice (1-4): "

if "%choice%"=="1" (
    echo.
    echo Stopping Ollama...
    taskkill /f /im ollama.exe >nul 2>&1
    taskkill /f /im "ollama app.exe" >nul 2>&1
    echo.
    echo Starting Ollama in CPU mode...
    set OLLAMA_MAX_VRAM=0
    set OLLAMA_LLM_LIBRARY=cpu
    start "" "ollama app.exe"
    echo Done. Ollama should now ignore the GPU.
    pause
    exit
)

if "%choice%"=="2" (
    echo.
    echo Stopping Ollama...
    taskkill /f /im ollama.exe >nul 2>&1
    taskkill /f /im "ollama app.exe" >nul 2>&1
    echo.
    echo Starting Ollama in default mode...
    set OLLAMA_MAX_VRAM=
    set OLLAMA_LLM_LIBRARY=
    start "" "ollama app.exe"
    echo Done.
    pause
    exit
)

if "%choice%"=="3" (
    echo.
    echo Checking connection to http://127.0.0.1:11434...
    powershell -Command "try { $res = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2; write-host 'Ollama is ONLINE'; $res.Content } catch { write-host 'Ollama is OFFLINE or UNREACHABLE' -ForegroundColor Red }"
    pause
    goto :eof
)

if "%choice%"=="4" exit

goto :eof
