# Server Deployment Guide

This directory contains the configurations and scripts required to set up the automated CI/CD deployment for the RAT Server.

## 1. Initial Server Setup (Manual)
You must perform these steps once on your remote server (VPS).

### A. Clone the Repository
SSH into your server and clone the repository to your home directory (or preferred location).
```bash
cd ~
git clone <YOUR_RECT_URL> rat-project
cd rat-project
```

### B. Run the Setup Script
This script creates the virtual environment, installs dependencies, and configures the `systemd` service.
```bash
chmod +x deployment/setup.sh
./deployment/setup.sh
```
*Note: This script requires `sudo` privileges to install the service file.*

### C. Configure Sudo Privileges
For GitHub Actions to restart the server without a password prompt, you must configure `sudoers`.

1. Edit the sudoers file:
   ```bash
   sudo visudo
   ```
2. Add the following line at the bottom (replace `your_username` with your actual Linux username):
   ```
   your_username ALL=(ALL) NOPASSWD: /bin/systemctl restart rat-server
   ```
3. Save and exit.

## 2. GitHub Configuration
To enable the automated workflow, add the following **Secrets** to your GitHub Repository settings (`Settings > Secrets and variables > Actions`):

| Secret Name       | Value                                         |
|-------------------|-----------------------------------------------|
| `SERVER_IP`       | Public IP address of your server              |
| `SERVER_USERNAME` | SSH Username (e.g., `ubuntu`, `root`)         |
| `SSH_PRIVATE_KEY` | Your private SSH key (content of `.pem` file) |
| `SERVER_PORT`     | (Optional) SSH port if not 22                 |

## 3. How It Works
1. When you push code to the `main` branch, the GitHub Action (`.github/workflows/deploy.yml`) triggers.
2. It connects to your server via SSH.
3. It navigates to `~/rat-project`, pulls the latest code, and updates dependencies.
4. It restarts the `rat-server` systemd service.
