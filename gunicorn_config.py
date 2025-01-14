import os
import multiprocessing

# Server socket configuration
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
backlog = 2048

# Worker configuration
workers = 4
worker_class = 'sync'  # Changed from uvicorn.workers.UvicornWorker to sync
threads = 4
worker_connections = 1000

# Timeout configuration
timeout = 300
keepalive = 5

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Process naming
proc_name = 'semgrep-analysis'

# Limits and stability
max_requests = 1000
max_requests_jitter = 50

# Development settings
reload = False
preload_app = True

# Security settings
forwarded_allow_ips = '*'
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}

# Application initialization hooks
def on_starting(server):
    """Log when server is starting"""
    server.log.info("Server is starting")

def post_fork(server, worker):
    """Configure worker after fork"""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def worker_abort(worker):
    """Log worker abort"""
    worker.log.info("Worker received SIGABRT signal")

# Resource cleanup
graceful_timeout = 30