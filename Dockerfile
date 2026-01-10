# Use a lightweight Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy the server source code
COPY server.py .

# Create directories for persistence mount points
RUN mkdir -p db files

# Expose the communication ports
EXPOSE 3131
EXPOSE 4131

# Run the server
CMD ["python", "server.py"]
