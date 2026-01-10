# Docker Deployment for RAT Server

This document outlines how to deploy the RAT Server using Docker and Docker Compose. This method replaces the legacy Systemd/Git workflow.

## Prerequisites

*   **Docker** and **Docker Compose** installed on the host machine.
*   Source code downloaded (specifically `Dockerfile`, `docker-compose.yml`, and `server.py`).

## File Structure

The deployment relies on the following files:

*   `Dockerfile`: Defines the Python environment and server application.
*   `docker-compose.yml`: Configures the service, ports, and volumes.
*   `.dockerignore`: Excludes unnecessary files (client code, venv, etc.) from the image.

## Deployment Steps

1.  **Build and Start the Server**
    Run the following command in the project root:
    ```bash
    docker-compose up -d --build
    ```
    *   `-d`: Detached mode (runs in background).
    *   `--build`: Forces a rebuild of the image (useful if you modified `server.py`).

2.  **View Logs**
    To see the server logs (e.g., client connections, errors):
    ```bash
    docker-compose logs -f
    ```

3.  **Stop the Server**
    ```bash
    docker-compose down
    ```

## Storage & Persistence

The server uses two Docker volumes mapped to the host to persist data:
*   `./db`: Stores the Admin database (`admins.json`).
*   `./files`: Stores uploaded files.

**Important:** Do not delete these folders on the host unless you intend to wipe all data.

## Ports

*   **3131**: Client Connection Port.
*   **4131**: Admin Console Connection Port.
