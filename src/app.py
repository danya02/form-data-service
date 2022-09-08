from flask import Flask, g, render_template, session, redirect, url_for, request, flash
from database import *
from utils import require_login

app = Flask(__name__)

db.connect()
app.secret_key = FlaskSecretKey.get_current()
db.close()


@app.before_request
def before_request():
    db.connect()
    g.user = None
    if 'user_id' in session:
        g.user = User.get_or_none(User.id == session['user_id'])


@app.after_request
def after_request(response):
    db.close()
    return response

@app.route('/')
def index():
    return 'Hello World!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            user = User.get_or_none(User.email == request.form['email'])
            if user and user.check_password(request.form['password']):
                session['user_id'] = user.id
                return redirect(request.form['next'])
            else:
                flash('login-error', 'error')
                return redirect(url_for('login', next=request.form.get('next', '/')))
        else:
            return render_template('login.html', next=request.args.get('next', '/'))
    except KeyError:
        flash('form-error', 'error')
        return redirect(url_for('login', next=request.args.get('next', '/')))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))