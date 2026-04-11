import gunicorn

# Override the server identification
gunicorn.SERVER_SOFTWARE = 'Apache/2.4.49 (Unix)'
gunicorn.SERVER = 'Apache/2.4.49 (Unix)'

def on_starting(server):
    """Patch after all gunicorn modules are loaded."""
    import gunicorn.http.wsgi
    gunicorn.http.wsgi.SERVER = 'Apache/2.4.49 (Unix)'
    gunicorn.http.wsgi.SERVER_SOFTWARE = 'Apache/2.4.49 (Unix)'

bind = '127.0.0.1:5000'
workers = 1
timeout = 30
