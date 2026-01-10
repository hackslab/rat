#!/bin/bash
set -e

# Ensure we are in the project root
cd "$(dirname "$0")/.."
PROJECT_DIR=$(pwd)
USER=$(whoami)
SERVICE_TEMPLATE="deployment/rat-server.service"

echo "--- RAT Server Setup ---"
echo "Project Directory: $PROJECT_DIR"
echo "User: $USER"

# 1. Setup Virtual Environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment (venv)..."
    python3 -m venv venv
else
    echo "[*] Virtual environment already exists."
fi

# 2. Install Dependencies
echo "[*] Installing dependencies from requirements-server.txt..."
if [ -f "requirements-server.txt" ]; then
    ./venv/bin/pip install -r requirements-server.txt
else
    echo "[!] requirements-server.txt not found, skipping pip install."
fi

# 3. Configure Systemd Service
echo "[*] Configuring systemd service..."

# We need to edit the template to replace <USER> and the path placeholders
# We create a temporary file for the customized service unit
TEMP_SERVICE_FILE="rat-server.service.tmp"

# Replace <USER> with current username
# Replace /home/<USER>/rat-project with the actual current directory ($PROJECT_DIR)
# Note: The template uses /home/<USER>/rat-project as a placeholder. 
# We will purely replace the specific strings if they exist, or just constructing it fresh might be safer?
# Let's rely on the template replacement as strictly defined in my previous turn.
# My template had: User=<USER>, WorkingDirectory=/home/<USER>/rat-project, ExecStart=/home/<USER>/rat-project/venv/bin/python
# So I need to replace /home/<USER>/rat-project with $PROJECT_DIR.

sed -e "s|<USER>|$USER|g" \
    -e "s|/home/$USER/rat-project|$PROJECT_DIR|g" \
    "$SERVICE_TEMPLATE" > "$TEMP_SERVICE_FILE"

echo "[*] Installing service file to /etc/systemd/system/ (requires sudo)..."
sudo mv "$TEMP_SERVICE_FILE" /etc/systemd/system/rat-server.service
sudo chown root:root /etc/systemd/system/rat-server.service
sudo chmod 644 /etc/systemd/system/rat-server.service

echo "[*] Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "[*] Enabling and starting rat-server service..."
sudo systemctl enable rat-server
sudo systemctl restart rat-server

echo "--- Setup Complete ---"
echo "Status:"
systemctl status rat-server --no-pager
