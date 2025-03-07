import os
import sys

# Print diagnostic information first
print("\n=== Environment Information ===")
print(f"Python version: {sys.version}")
print(f"Current working directory: {os.getcwd()}")
print(f"Environment variables:")
print(f"- PORT: {os.getenv('PORT')}")
print(f"- FLASK_ENV: {os.getenv('FLASK_ENV')}")
print("===========================\n")

# Bind configuration - using direct string instead of list
bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
print(f"Setting bind address to: {bind}")

# Worker configuration
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "debug"

# Additional settings to ensure proper binding
preload_app = True
forwarded_allow_ips = '*'

def on_starting(server):
    """This hook runs when Gunicorn starts up, before any workers"""
    print("\n=== Pre-start Configuration ===")
    port = os.getenv("PORT", "8000")
    print(f"Setting bind to port {port}")
    server.app.cfg.bind = [f"0.0.0.0:{port}"]

# Print environment information
print("=== Gunicorn Configuration ===")
print(f"Python version: {sys.version}")
print(f"Current working directory: {os.getcwd()}")
print(f"Environment variables:")
print(f"- PORT: {os.getenv('PORT')}")
print(f"- FLASK_ENV: {os.getenv('FLASK_ENV')}")
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
loglevel = "debug"  # Keep debug level for detailed logging 
