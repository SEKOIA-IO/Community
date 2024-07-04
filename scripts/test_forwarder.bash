#!/bin/bash

# Docker container name
IMAGE_NAME="sekoiaio-docker-concentrator"
CURRENT_TIME_ISO=$(date '+%Y-%m-%dT%H:%M:%S%z')
EXEC_FILE="execution.txt"
INSPECT_FILE="inspect.txt"
LOGS_FILE="logs.txt"
PCAP_FILE="capture.pcap"
TCPDUMP_TIMEOUT=30
RESULT_FOLDER="result_$(date '+%Y-%m-%dT%H_%M_%S%z')"
DST_PORT=10514

# List of programm to check if they are installed
PROGRAMS_APT=("tcpdump" "coreutils" "nc")
PROGRAMS_DNF=("tcpdump" "coreutils" "nmap-ncat")

# Function to check and install programs on Debian/Ubuntu-based distributions
install_apt() {
    apt update
    for PROGRAM in "${PROGRAMS_APT[@]}"; do
        if ! dpkg -l | grep -q "^ii  $PROGRAM "; then
            echo "  - $PROGRAM is not installed. Installing..."
            apt install -y $PROGRAM
        else
            echo "  - $PROGRAM is already installed."
        fi
    done
}

# Function to check and install programs on Red Hat/CentOS/Fedora-based distributions
install_dnf() {
    if command -v dnf &> /dev/null; then
        # Use dnf if availabe
        for PROGRAM in "${PROGRAMS_DNF[@]}"; do
            if ! rpm -q $PROGRAM &> /dev/null; then
                echo "  * $PROGRAM is not installed. Installing..."
                dnf install -y $PROGRAM
            else
                echo "  * $PROGRAM is already installed."
            fi
        done
    elif command -v yum &> /dev/null; then
        # Otherwise, use yum
        for PROGRAM in "${PROGRAMS_DNF[@]}"; do
            if ! rpm -q $PROGRAM &> /dev/null; then
                echo "  * $PROGRAM is not installed. Installing..."
                yum install -y $PROGRAM
            else
                echo "  * $PROGRAM is already installed."
            fi
        done
    else
        echo "  * Neither dnf nor yum found. Cannot install packages."
        tar -czf result_files.tar.gz result_*
        exit 1
    fi
}

install_packages() {
    # Detection of the distribution and call to the appropriate function
    echo "- Check if some necessary packages are installed:"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian)
                install_apt
                ;;
            fedora|centos|rhel)
                install_dnf
                ;;
            *)
                echo "  * Distribution not supported : $ID"
                tar -czf result_files.tar.gz result_*
                exit 1
                ;;
        esac
    else
        echo "  * File /etc/os-release not found. Unable to detect the distribution."
        tar -czf result_files.tar.gz result_*
        exit 1
    fi
}


# Function to print a separator line
print_separator() {
    echo "#####################################################################"
}

# Start of the script, redirecting output to `result.txt` while also displaying on the terminal
print_separator
echo "# Sekoia.io script that check the status of the Sekoia.io forwarder #"
print_separator

# Get the region if specified
LOCATION=${1:-FRA1}
LOCATION=$(echo "$LOCATION" | tr '[:lower:]' '[:upper:]')

case "$LOCATION" in
    FRA1)
        HOST="intake.sekoia.io"
        ;;
    FRA2)
        HOST="fra2.app.sekoia.io"
        ;;
    MCO1)
        HOST="mco1.app.sekoia.io"
        ;;
    UAE1)
        HOST="app.uae1.sekoia.io"
        ;;
    # Ajoutez d'autres cas ici
    *)
        echo "Unknown location: $LOCATION"
        tar -czf result_files.tar.gz result_*
        exit 1
        ;;
esac

# Create result folder
mkdir $RESULT_FOLDER
echo "- Creating result folder: OK"

# Current timestamp
echo "- Timestamp: $CURRENT_TIME_ISO" | tee -a $RESULT_FOLDER/$EXEC_FILE

# Current path
echo "- Current path: `pwd`" | tee -a $RESULT_FOLDER/$EXEC_FILE

# OS
echo "- OS: `uname -a`" | tee -a $RESULT_FOLDER/$EXEC_FILE

# Get docker-compose.yml and intakes.yml
echo "- Get docker-compose and intakes files"
cp docker-compose.yml intakes.yaml $RESULT_FOLDER

# Check if docker is installed and get the version
if ! command -v docker &> /dev/null
then
    echo "- Docker could not be found" | tee -a $RESULT_FOLDER/$EXEC_FILE
    tar -czf result_files.tar.gz result_*
    exit 1
fi
echo "- Docker version: `docker --version`" | tee -a $RESULT_FOLDER/$EXEC_FILE

# Check if the Docker container is running
# Get the Docker container ID associated with the image name
docker_id=$(docker ps | grep "$IMAGE_NAME" | awk '{print $1}')

# Check if the docker_id variable is non-empty, which indicates that the container is running
if [ -n "$docker_id" ]; then
    echo "- Container is running: OK" | tee -a $RESULT_FOLDER/$EXEC_FILE
else
    echo "- Container is running: KO" | tee -a $RESULT_FOLDER/$EXEC_FILE
    tar -czf result_files.tar.gz result_*
    exit 1
fi 

# Get information from docker inspect
echo "- Getting container information from docker inspect into inspect.txt"
docker inspect $docker_id > $RESULT_FOLDER/$INSPECT_FILE

install_packages | tee -a $RESULT_FOLDER/$EXEC_FILE

# Checking outbound flow to intake.sekoia.io
echo "- Checking if the connection to $HOST:$PORT is opened..."
if nc -zv "$HOST" "$DST_PORT" &> /dev/null; then
    echo "- Port $DST_PORT on $HOST is opened." | tee -a $RESULT_FOLDER/$EXEC_FILE
else
    echo "- Port $DST_PORT on $HOST is closed." | tee -a $RESULT_FOLDER/$EXEC_FILE
fi

# Get docker logs
echo "- Getting container logs"
docker logs --tail 10000 $docker_id &> $RESULT_FOLDER/$LOGS_FILE

echo "- Starting $TCPDUMP_TIMEOUT seconds of tcpdump... please wait."
timeout $TCPDUMP_TIMEOUT tcpdump portrange 20000-30000 -q -n -s 0 -w $RESULT_FOLDER/$PCAP_FILE

echo "End of tests."
echo "Compressing the data into an archive."
tar -czf result_files.tar.gz result_*
