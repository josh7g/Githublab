import os
import multiprocessing

# Server socket configuration
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
backlog = 2048

# Worker configuration
workers = 4
worker_class = 'uvicorn.workers.UvicornWorker'  # Changed for ASGI support
threads = 4
worker_connections = 1000

# Timeout configuration
timeout = 300  # Increased for long-running operations
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

# Application initialization hooks
def on_starting(server):
    """Log when server is starting"""
    server.log.info("Server is starting")
    # Ensure the event loop is configured for async operations
    import asyncio
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

def post_fork(server, worker):
    """Configure worker after fork"""
    server.log.info(f"Worker spawned (pid: {worker.pid})")
    # Ensure each worker has its own event loop
    import asyncio
    asyncio.set_event_loop(asyncio.new_event_loop())

# Other settings remain the same...