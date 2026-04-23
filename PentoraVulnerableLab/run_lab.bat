@echo off
setlocal enabledelayedexpansion

:main_menu
cls
echo Pentora Vulnerable Lab - Interactive Menu
echo ==========================================
echo.
echo Available options:
echo.
echo  1) Start lab
echo  2) Start lab without browser
echo  3) Stop lab
echo  4) Check lab status
echo  5) Rebuild lab
echo  6) View lab logs
echo  7) Open shell in lab container
echo  8) Run lab on custom port
echo  9) Create scan target file
echo  0) Exit
echo.
echo  h) Help - Show detailed command information
echo.

set /p choice="Enter your choice (0-9 or h): "

if "%choice%"=="1" goto start_lab
if "%choice%"=="2" goto start_lab_no_browser
if "%choice%"=="3" goto stop_lab
if "%choice%"=="4" goto check_status
if "%choice%"=="5" goto rebuild_lab
if "%choice%"=="6" goto view_logs
if "%choice%"=="7" goto open_shell
if "%choice%"=="8" goto custom_port
if "%choice%"=="9" goto create_scan_target
if "%choice%"=="0" goto exit_script
if /i "%choice%"=="h" goto show_help
if /i "%choice%"=="help" goto show_help

echo Invalid choice. Please try again.
timeout /t 2 >nul
goto main_menu

:start_lab
call :check_docker
if %errorlevel% neq 0 goto main_menu_after_pause
goto run_container

:start_lab_no_browser
set no_browser=true
call :check_docker
if %errorlevel% neq 0 goto main_menu_after_pause
goto run_container

:stop_lab
echo Stopping Pentora Vulnerable Lab...
docker stop pentora-lab >nul 2>&1
if !errorlevel! equ 0 (
    echo Container stopped successfully.
    docker rm pentora-lab >nul 2>&1
    echo Container removed.
) else (
    echo No running container found.
)
goto main_menu_after_pause

:check_status
echo Checking Pentora Vulnerable Lab status...
docker ps | findstr pentora-lab >nul 2>&1
if !errorlevel! equ 0 (
    echo Pentora Vulnerable Lab is RUNNING
    echo Access it at: http://localhost:8000
) else (
    docker ps -a | findstr pentora-lab >nul 2>&1
    if !errorlevel! equ 0 (
        echo Pentora Vulnerable Lab is STOPPED
        echo To start it, select option 1 from the menu.
    ) else (
        echo Pentora Vulnerable Lab is NOT INSTALLED
        echo To install it, select option 1 from the menu.
    )
)
goto main_menu_after_pause

:rebuild_lab
echo Rebuilding Pentora Vulnerable Lab...
docker stop pentora-lab >nul 2>&1
docker rm pentora-lab >nul 2>&1
docker rmi pentora-vulnerable-lab >nul 2>&1
echo Building fresh image...
docker build -t pentora-vulnerable-lab .
if !errorlevel! neq 0 (
    echo Error: Failed to build Docker image.
    goto main_menu_after_pause
)

echo Would you like to start the lab now? (Y/N)
set /p start_now="Choice: "
if /i "!start_now!"=="y" (
    goto run_container
) else (
    echo Image rebuilt successfully.
    goto main_menu_after_pause
)

:view_logs
echo Displaying logs for Pentora Vulnerable Lab...
docker logs pentora-lab
echo.
echo Press any key to return to the menu...
pause >nul
goto main_menu

:open_shell
echo Opening shell in Pentora Vulnerable Lab container...
echo (Type 'exit' to return to this menu)
echo.
docker exec -it pentora-lab /bin/bash
goto main_menu

:custom_port
echo Enter the port number to run the lab on:
set /p port_number="Port: "

if "!port_number!"=="" (
    echo Error: Port number required.
    goto main_menu_after_pause
)

echo Stopping existing container if running...
docker stop pentora-lab >nul 2>&1
docker rm pentora-lab >nul 2>&1

echo Starting Pentora Vulnerable Lab on port !port_number!...
docker run -d --name pentora-lab -p !port_number!:80 pentora-vulnerable-lab

if !errorlevel! neq 0 (
    echo Error: Failed to start container on port !port_number!.
    goto main_menu_after_pause
)

echo Pentora Vulnerable Lab is now running on port !port_number!!
echo Access it at: http://localhost:!port_number!

echo Opening lab in default browser...
start http://localhost:!port_number!

goto main_menu_after_pause

:create_scan_target
echo Setting up Pentora to scan the lab...
docker ps | findstr pentora-lab >nul 2>&1
if !errorlevel! neq 0 (
    echo Error: Pentora Vulnerable Lab is not running.
    echo Please start it first with option 1 from the menu.
    goto main_menu_after_pause
)

echo http://localhost:8000 > .lab_target
echo Lab target saved to .lab_target file.
echo You can now use this target in Pentora.
goto main_menu_after_pause

:check_docker
REM Check if Docker is installed
echo Checking if Docker is installed...
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Docker is not installed or not in PATH.
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop/
    exit /b 1
)

REM Check if Docker is running
echo Checking if Docker is running...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Docker is not running.
    echo Please start Docker Desktop and try again.
    exit /b 1
)

REM Check if container is already running
echo Checking if Pentora Vulnerable Lab is already running...
docker ps | findstr pentora-lab >nul 2>&1
if %errorlevel% equ 0 (
    echo.
    echo Pentora Vulnerable Lab is already running!
    echo Access it at: http://localhost:8000
    echo.
    
    if not defined no_browser (
        echo Opening lab in default browser...
        start http://localhost:8000
    )
    
    exit /b 1
)

REM Check if container exists but is stopped
docker ps -a | findstr pentora-lab >nul 2>&1
if %errorlevel% equ 0 (
    echo Found stopped container. Removing it to start fresh...
    docker rm pentora-lab >nul 2>&1
)

REM Check if image exists
echo Checking for existing Pentora Vulnerable Lab image...
docker images | findstr pentora-vulnerable-lab >nul 2>&1
if %errorlevel% neq 0 (
    echo Building Pentora Vulnerable Lab Docker image...
    docker build -t pentora-vulnerable-lab .
    if %errorlevel% neq 0 (
        echo Error: Failed to build Docker image.
        exit /b 1
    )
) else (
    echo Pentora Vulnerable Lab image found.
)

exit /b 0

:run_container
REM Run the container
echo Starting Pentora Vulnerable Lab container...
docker run -d --name pentora-lab -p 8000:80 pentora-vulnerable-lab

if %errorlevel% neq 0 (
    echo Error: Failed to start the container.
    echo Attempting to clean up any existing containers...
    docker rm pentora-lab >nul 2>&1
    echo Please try running the script again.
    goto main_menu_after_pause
)

echo.
echo Pentora Vulnerable Lab is now running!
echo Access it at: http://localhost:8000
echo.

REM Wait a moment for the container to fully start
echo Waiting for the lab to initialize...
timeout /t 3 /nobreak >nul

REM Launch browser automatically if not disabled
if not defined no_browser (
    echo Opening lab in default browser...
    start http://localhost:8000
)

echo.
echo If the page doesn't load immediately, please wait a few seconds and refresh.
echo The lab may take a moment to fully initialize.

set no_browser=
goto main_menu_after_pause

:show_help
cls
echo.
echo Pentora Vulnerable Lab - Command Line Interface Help
echo =================================================
echo.
echo Available commands:
echo.
echo  1) Start lab             - Start the Pentora Vulnerable Lab
echo  2) Start without browser - Start the lab without opening the browser
echo  3) Stop lab              - Stop and remove the lab container
echo  4) Check status          - Check the current status of the lab
echo  5) Rebuild lab           - Rebuild the Docker image from scratch
echo  6) View logs             - Display the container logs
echo  7) Open shell            - Open a shell in the running container
echo  8) Custom port           - Run the lab on a specific port
echo  9) Create scan target    - Create a target file for Pentora scanner
echo  0) Exit                  - Exit this menu
echo.
echo Command Line Usage:
echo   run_lab.bat start           - Start the lab and open in browser
echo   run_lab.bat stop            - Stop the running lab
echo   run_lab.bat port 8080       - Run the lab on port 8080
echo   run_lab.bat help            - Display this help message
echo.
echo Press any key to return to the menu...
pause >nul
goto main_menu

:main_menu_after_pause
echo.
echo Press any key to return to the menu...
pause >nul
goto main_menu

:exit_script
echo Exiting Pentora Vulnerable Lab menu.
endlocal
exit /b 0
