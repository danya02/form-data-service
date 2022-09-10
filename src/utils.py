from flask import g, redirect, url_for, request, flash
from functools import wraps

def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not g.user:
            flash('login-required', 'error')
            return redirect(url_for('login', next=request.url))
        return func(*args, **kwargs)
    return wrapper