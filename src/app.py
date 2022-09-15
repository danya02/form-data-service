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
    db.close()
    return response

register_blueprints_on_app(app)

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()], render_kw={'placeholder': 'alice@example.com'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'placeholder': 'passw0rd'})
    next = HiddenField(default='/')

@app.route('/')
@require_login
def index():
    return redirect(url_for('projects.index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(data={'next': request.args.get('next')})
    if form.validate_on_submit():
        user = User.get_or_none(User.email == form.email.data)
        if user is None:
            flash('login-error', 'error')
        else:
            if user.check_password(form.password.data):
                session['user_id'] = user.id
                return redirect(form.next.data or url_for('index'))
            else:
                flash('login-error', 'error')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))