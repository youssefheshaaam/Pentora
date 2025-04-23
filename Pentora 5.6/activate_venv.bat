@echo off
echo Pentora - Vulnerability Scanner
echo ==============================

REM Check if venv exists
if not exist venv\ (
    echo Virtual environment not found. Creating new environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error creating virtual environment. Please ensure Python is installed correctly.
        pause
        exit /b 1
    )
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing/updating requirements...
pip install -r requirements.txt
if errorlevel 1 (
    echo Error installing requirements. Please check your internet connection.
    pause
    exit /b 1
)

echo Starting Pentora...
python pentora.py
if errorlevel 1 (
    echo Pentora exited with an error.
    pause
)

deactivate
