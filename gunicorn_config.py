import os

# Bind to PORT if provided, otherwise default to 8000
port = os.getenv("PORT", "8000")
bind = f"0.0.0.0:{port}"

# Worker configuration
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info" 