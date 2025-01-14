import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
backlog = 2048

# Workers
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'gunicorn.workers.gthread.ThreadWorker'  # Changed worker class
threads = 4

# Timeout
timeout = 300
keepalive = 5

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# SSL/TLS Settings
forwarded_allow_ips = '*'
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}

# Process Naming
proc_name = 'semgrep-analysis'

# Server Mechanics
preload_app = True
reload = False

# Debugging
capture_output = True
enable_stdio_inheritance = True

# Limits
max_requests = 1000
max_requests_jitter = 50
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

def when_ready(server):
    """Log when server is ready"""
    server.log.info("Server is ready. Spawning workers")

def on_starting(server):
    """Log when server is starting"""
    server.log.info("Server is starting")

def post_fork(server, worker):
    """Log worker spawn"""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

# Worker Recycling
max_requests = 1000
max_requests_jitter = 50
graceful_timeout = 30