import os
import sys

# Force port 8000 for Render
bind = "0.0.0.0:8000"

# Print environment information
print("=== Gunicorn Configuration ===")
print(f"Python version: {sys.version}")
print(f"Current working directory: {os.getcwd()}")
print(f"Environment variables:")
print(f"- PORT: {os.getenv('PORT')}")
print(f"- FLASK_ENV: {os.getenv('FLASK_ENV')}")
print(f"Binding to: {bind}")
print("===========================")

# Worker configuration
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "debug"  # Changed to debug for more detailed logging 
