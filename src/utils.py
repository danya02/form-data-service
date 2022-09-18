from flask import g, redirect, url_for, request, flash, session
from functools import wraps

def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not g.user:
            flash('requires-login', 'warning')
            return redirect(url_for('login.login', next=request.url))
        if session.get('login_state') == 'perform_2fa':
            flash('login-then-2fa', 'success')
            return redirect(url_for('login_2fa'), next=request.url)
        if session.get('login_state') == 'completed':
            return func(*args, **kwargs)
    return wrapper