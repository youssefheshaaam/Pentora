#!/bin/bash

# Function to open browser on different platforms
open_browser() {
    local url=$1
    echo "Opening lab in default browser..."
    if command -v xdg-open &>/dev/null; then
        xdg-open "$url" &
    elif command -v open &>/dev/null; then
        open "$url" &
    elif command -v start &>/dev/null; then
        start "$url" &
    else
        echo "Could not automatically open browser. Please navigate to $url"
    fi
}

# Function to check docker and container status
check_docker() {
    # Check if Docker is installed
    echo "Checking if Docker is installed..."
    if ! command -v docker &>/dev/null; then
        echo "Error: Docker is not installed or not in PATH."
        echo "Please install Docker from https://www.docker.com/products/docker-desktop/"
        return 1
    fi

    # Check if Docker is running
    echo "Checking if Docker is running..."
    docker info &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Docker is not running."
        echo "Please start Docker Desktop and try again."
        return 1
    fi

    # Check if container is already running
    echo "Checking if Pentora Vulnerable Lab is already running..."
    if docker ps | grep -q pentora-lab; then
        echo
        echo "Pentora Vulnerable Lab is already running!"
        echo "Access it at: http://localhost:8000"
        echo
        
        if [ -z "$NO_BROWSER" ]; then
            open_browser "http://localhost:8000"
        fi
        
        return 1
    fi

    # Check if container exists but is stopped
    if docker ps -a | grep -q pentora-lab; then
        echo "Found stopped container. Removing it to start fresh..."
        docker rm pentora-lab &>/dev/null
    fi

    # Check if image exists
    echo "Checking for existing Pentora Vulnerable Lab image..."
    if ! docker images | grep -q pentora-vulnerable-lab; then
        echo "Building Pentora Vulnerable Lab Docker image..."
        docker build -t pentora-vulnerable-lab .
        if [ $? -ne 0 ]; then
            echo "Error: Failed to build Docker image."
            return 1
        fi
    else
        echo "Pentora Vulnerable Lab image found."
    fi
    
    return 0
}

# Function to run the container
run_container() {
    # Run the container
    echo "Starting Pentora Vulnerable Lab container..."
    docker run -d --name pentora-lab -p 8000:80 pentora-vulnerable-lab

    if [ $? -ne 0 ]; then
        echo "Error: Failed to start the container."
        echo "Attempting to clean up any existing containers..."
        docker rm pentora-lab &>/dev/null
        echo "Please try running the script again."
        return 1
    fi

    echo
    echo "Pentora Vulnerable Lab is now running!"
    echo "Access it at: http://localhost:8000"
    echo

    # Wait a moment for the container to fully start
    echo "Waiting for the lab to initialize..."
    sleep 3

    # Launch browser automatically if not disabled
    if [ -z "$NO_BROWSER" ]; then
        open_browser "http://localhost:8000"
    fi

    echo
    echo "If the page doesn't load immediately, please wait a few seconds and refresh."
    echo "The lab may take a moment to fully initialize."
    
    # Reset the no browser flag
    NO_BROWSER=""
    
    return 0
}

# Function to display help
show_help() {
    clear
    echo
    echo "Pentora Vulnerable Lab - Command Line Interface Help"
    echo "==================================================="
    echo
    echo "Available commands:"
    echo
    echo " 1) Start lab             - Start the Pentora Vulnerable Lab"
    echo " 2) Start without browser - Start the lab without opening the browser"
    echo " 3) Stop lab              - Stop and remove the lab container"
    echo " 4) Check status          - Check the current status of the lab"
    echo " 5) Rebuild lab           - Rebuild the Docker image from scratch"
    echo " 6) View logs             - Display the container logs"
    echo " 7) Open shell            - Open a shell in the running container"
    echo " 8) Custom port           - Run the lab on a specific port"
    echo " 9) Create scan target    - Create a target file for Pentora scanner"
    echo " 0) Exit                  - Exit this menu"
    echo
    echo "Command Line Usage:"
    echo "  ./run_lab.sh start           - Start the lab and open in browser"
    echo "  ./run_lab.sh stop            - Stop the running lab"
    echo "  ./run_lab.sh port 8080       - Run the lab on port 8080"
    echo "  ./run_lab.sh help            - Display this help message"
    echo
    echo "Press Enter to return to the menu..."
    read
}

# Function to stop the lab
stop_lab() {
    echo "Stopping Pentora Vulnerable Lab..."
    docker stop pentora-lab &>/dev/null
    if [ $? -eq 0 ]; then
        echo "Container stopped successfully."
        docker rm pentora-lab &>/dev/null
        echo "Container removed."
    else
        echo "No running container found."
    fi
}

# Function to check lab status
check_status() {
    echo "Checking Pentora Vulnerable Lab status..."
    if docker ps | grep -q pentora-lab; then
        echo "Pentora Vulnerable Lab is RUNNING"
        echo "Access it at: http://localhost:8000"
    else
        if docker ps -a | grep -q pentora-lab; then
            echo "Pentora Vulnerable Lab is STOPPED"
            echo "To start it, select option 1 from the menu."
        else
            echo "Pentora Vulnerable Lab is NOT INSTALLED"
            echo "To install it, select option 1 from the menu."
        fi
    fi
}

# Function to rebuild the lab
rebuild_lab() {
    echo "Rebuilding Pentora Vulnerable Lab..."
    docker stop pentora-lab &>/dev/null
    docker rm pentora-lab &>/dev/null
    docker rmi pentora-vulnerable-lab &>/dev/null
    echo "Building fresh image..."
    docker build -t pentora-vulnerable-lab .
    if [ $? -ne 0 ]; then
        echo "Error: Failed to build Docker image."
        return 1
    fi
    
    echo "Would you like to start the lab now? (y/n)"
    read -r start_now
    if [[ "$start_now" =~ ^[Yy] ]]; then
        run_container
    else
        echo "Image rebuilt successfully."
    fi
}

# Function to run on custom port
run_custom_port() {
    echo "Enter the port number to run the lab on:"
    read -r port_number
    
    if [ -z "$port_number" ]; then
        echo "Error: Port number required."
        return 1
    fi
    
    echo "Stopping existing container if running..."
    docker stop pentora-lab &>/dev/null
    docker rm pentora-lab &>/dev/null
    
    echo "Starting Pentora Vulnerable Lab on port $port_number..."
    docker run -d --name pentora-lab -p "$port_number:80" pentora-vulnerable-lab
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to start container on port $port_number."
        return 1
    fi
    
    echo "Pentora Vulnerable Lab is now running on port $port_number!"
    echo "Access it at: http://localhost:$port_number"
    
    # Launch browser automatically
    open_browser "http://localhost:$port_number"
}

# Function to create scan target
create_scan_target() {
    echo "Setting up Pentora to scan the lab..."
    if ! docker ps | grep -q pentora-lab; then
        echo "Error: Pentora Vulnerable Lab is not running."
        echo "Please start it first with option 1 from the menu."
        return 1
    fi
    
    echo "http://localhost:8000" > .lab_target
    echo "Lab target saved to .lab_target file."
    echo "You can now use this target in Pentora."
}

# Check for command line arguments
if [ $# -gt 0 ]; then
    case "$1" in
        "help"|"-h"|"--help")
            show_help
            exit 0
            ;;
        "stop")
            stop_lab
            exit 0
            ;;
        "status")
            check_status
            exit 0
            ;;
        "logs")
            echo "Displaying logs for Pentora Vulnerable Lab..."
            docker logs pentora-lab
            exit 0
            ;;
        "shell")
            echo "Opening shell in Pentora Vulnerable Lab container..."
            docker exec -it pentora-lab /bin/bash
            exit 0
            ;;
        "port")
            if [ -z "$2" ]; then
                echo "Error: Port number required."
                echo "Usage: ./run_lab.sh port PORT_NUMBER"
                exit 1
            fi
            
            echo "Stopping existing container if running..."
            docker stop pentora-lab &>/dev/null
            docker rm pentora-lab &>/dev/null
            
            echo "Starting Pentora Vulnerable Lab on port $2..."
            docker run -d --name pentora-lab -p "$2:80" pentora-vulnerable-lab
            
            if [ $? -ne 0 ]; then
                echo "Error: Failed to start container on port $2."
                exit 1
            fi
            
            echo "Pentora Vulnerable Lab is now running on port $2!"
            echo "Access it at: http://localhost:$2"
            
            # Launch browser automatically
            open_browser "http://localhost:$2"
            
            exit 0
            ;;
        "scan")
            create_scan_target
            exit 0
            ;;
        "rebuild")
            echo "Rebuilding Pentora Vulnerable Lab..."
            docker stop pentora-lab &>/dev/null
            docker rm pentora-lab &>/dev/null
            docker rmi pentora-vulnerable-lab &>/dev/null
            echo "Building fresh image..."
            docker build -t pentora-vulnerable-lab .
            if [ $? -ne 0 ]; then
                echo "Error: Failed to build Docker image."
                exit 1
            fi
            
            if [ "$2" = "--no-start" ]; then
                echo "Image rebuilt successfully. Use './run_lab.sh start' to run the lab."
                exit 0
            fi
            
            check_docker
            if [ $? -eq 0 ]; then
                run_container
            fi
            exit 0
            ;;
        "start")
            if [ "$2" = "--no-browser" ]; then
                NO_BROWSER=true
            fi
            check_docker
            if [ $? -eq 0 ]; then
                run_container
            fi
            exit 0
            ;;
        *)
            echo "Unknown command: $1"
            echo "Run './run_lab.sh help' to see available commands."
            exit 1
            ;;
    esac
fi

# Main menu loop
while true; do
    clear
    echo "Pentora Vulnerable Lab - Interactive Menu"
    echo "=========================================="
    echo
    echo "Available options:"
    echo
    echo " 1) Start lab"
    echo " 2) Start lab without browser"
    echo " 3) Stop lab"
    echo " 4) Check lab status"
    echo " 5) Rebuild lab"
    echo " 6) View lab logs"
    echo " 7) Open shell in lab container"
    echo " 8) Run lab on custom port"
    echo " 9) Create scan target file"
    echo " 0) Exit"
    echo
    echo " h) Help - Show detailed command information"
    echo
    
    read -p "Enter your choice (0-9 or h): " choice
    
    case "$choice" in
        1)
            check_docker
            if [ $? -eq 0 ]; then
                run_container
            fi
            ;;
        2)
            NO_BROWSER=true
            check_docker
            if [ $? -eq 0 ]; then
                run_container
            fi
            ;;
        3)
            stop_lab
            ;;
        4)
            check_status
            ;;
        5)
            rebuild_lab
            ;;
        6)
            echo "Displaying logs for Pentora Vulnerable Lab..."
            docker logs pentora-lab
            ;;
        7)
            echo "Opening shell in Pentora Vulnerable Lab container..."
            echo "(Type 'exit' to return to this menu)"
            echo
            docker exec -it pentora-lab /bin/bash
            ;;
        8)
            run_custom_port
            ;;
        9)
            create_scan_target
            ;;
        0|q|Q)
            echo "Exiting Pentora Vulnerable Lab menu."
            exit 0
            ;;
        h|H|help)
            show_help
            ;;
        *)
            echo "Invalid choice. Please try again."
            sleep 2
            continue
            ;;
    esac
    
    if [ "$choice" != "7" ]; then
        echo
        echo "Press Enter to return to the menu..."
        read
    fi
done
