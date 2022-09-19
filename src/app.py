from flask import Flask, g, render_template, session, redirect, url_for, request, flash
from database import *
from utils import require_login
from blueprints import register_blueprints_on_app
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import PasswordField, HiddenField, EmailField
from wtforms.validators import DataRequired, Email

from ingress import bp as ingress_bp
app = Flask(__name__)

db.connect()
app.secret_key = FlaskSecretKey.get_current()
db.close()

csrf = CSRFProtect(app)
csrf.exempt(ingress_bp)

@app.before_request
def before_request():
    # NB: This is used to get the real IP address from Cloudflare.
    # Cloudflare sets the CF-Connecting-IP header.
    # We will trust it directly if present -- if you are not using Cloudflare like this, this is a security risk!
    # If you are not using Cloudflare, you should remove this line.
    request.remote_addr = request.headers.get('CF-Connecting-IP', request.remote_addr) 
    db.connect()
    g.user = None
    if 'user_id' in session:
        g.user = User.get_or_none(User.id == session['user_id'])

@app.after_request
def after_request(response):

    # If the request was to the ingress, we need to set the Access-Control-Allow-Origin header.
    # This is because the ingress is a separate domain from the main site.

    if request.path.startswith('/ingress'):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept, Authorization, X-Request-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'

    db.close()
    return response

register_blueprints_on_app(app)

@app.route('/')
@require_login
def index():
    return redirect(url_for('projects.index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login.login'))