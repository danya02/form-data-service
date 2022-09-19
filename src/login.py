from flask import Blueprint, request, render_template, redirect, url_for, flash, session, g, make_response
from flask_wtf import FlaskForm
from wtforms import PasswordField, HiddenField, EmailField
from wtforms.validators import DataRequired, Length
from database import *
from utils import require_login
import qrcode
import pyotp
import io
import requests
import hashlib

bp = Blueprint('login', __name__, url_prefix='/login')

def check_password_pwnage(password: str) -> bool:
    """
    Check for password pwnage using the Have I Been Pwned Passwords API.
    Per the acceptable use policy, uses a User-agent that links to this project's repository.
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    resp = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', headers={'User-agent': 'Python-Requests/2 (+Forms Data Service; https://github.com/danya02/form-data-service)'})
    if resp.status_code != 200:
        return False
    for line in resp.text.splitlines():
        if line.startswith(suffix):
            return True
    return False

class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()], render_kw={'placeholder': 'alice@example.com'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'placeholder': 'passw0rd'})

@bp.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_or_none(User.email == form.email.data)
        if user is None:
            flash('login-error', 'error')
        else:
            if user.check_password(form.password.data):
                session['user_id'] = user.id
                if check_password_pwnage(form.password.data):
                    flash('login-ok-password-is-pwned', 'warning')
                    user.pwned_login_count -= 1
                    user.save()
                if user.totp_secret is not None:
                    session['login_state'] = 'perform_2fa'
                    return redirect(url_for('.login_2fa', next=request.args.get('next', '/')))
                else:
                    session['login_state'] = 'completed'
                    return redirect(request.args.get('next') or url_for('index'))

            else:
                flash('login-error', 'error')
    return render_template('login.html', form=form, submit_url=url_for('.login', next=request.args.get('next') or '/'))

@bp.route('/2fa')
def login_2fa():
    # If the user has not used a password yet, redirect them to the login page.
    if g.user is None:
        return redirect(url_for('.login'), next=request.args.get('next', '/'))
    # If the user doesn't need to do 2FA, redirect them to the target page.
    if session.get('login_state') != 'perform_2fa':
        return redirect(request.args.get('next', '/'))
    # If the user needs to do 2FA, then show them the 2FA page.
    # If they have only TOTP, then show them the TOTP page.
    # If they have only U2F, then show them the U2F page.
    # If they have both, then show them the U2F page.
    elif g.user.totp_enabled:
        return redirect(url_for('.login_2fa_totp', next=request.args.get('next', '/')))
    else:
        flash('login-error-bug', 'info')

class TOTPForm(FlaskForm):
    totp = PasswordField('TOTP', validators=[DataRequired()], render_kw={'placeholder': '123456'})
    totp_secret = HiddenField('TOTP Secret')  # Only passed in when the user is setting up TOTP, ignored when the user is logging in.

@bp.route('/2fa/totp', methods=['GET', 'POST'])
def login_2fa_totp():
    if g.user is None:
        return redirect(url_for('.login'))
    if session.get('login_state') != 'perform_2fa':
        return redirect(request.args.get('next') or url_for('.index'))
    if g.user.totp_secret is None:
        return redirect(url_for('.login_2fa'))

    form = TOTPForm()
    if form.validate_on_submit():
        result, reason = g.user.check_totp_code(form.totp.data)
        if result:
            session['login_state'] = 'completed'
            return redirect(request.args.get('next') or url_for('index'))
        else:
            flash(reason, 'danger')
    return render_template('login-2fa-totp.html', form=form, submit_url=url_for('.login_2fa_totp', next=request.args.get('next', '/')))

@bp.route('/2fa/totp/config')
@require_login
def totp_config():
    secret = pyotp.random_base32()
    new_otp = pyotp.TOTP(secret)
    provision_url = new_otp.provisioning_uri(g.user.email, issuer_name='Forms Data Server')
    form = TOTPForm(totp_secret=secret)
    return render_template('login-2fa-totp-config.html', totp_form=form, totp_secret=secret, totp_qr=url_for('.totp_tools_qr', q=provision_url))

@bp.route('/2fa/totp/config/reset_codes', methods=['POST'])
@require_login
def totp_config_reset_codes():
    g.user.generate_totp_recovery_codes()
    g.user.save()
    flash('totp-recovery-codes-reset', 'success')
    return redirect(url_for('.totp_config'))

@bp.route('/2fa/totp/tools/qr')
@require_login
def totp_tools_qr():
    string = request.args['q']
    img = qrcode.make(string)
    fp = io.BytesIO()
    img.save(fp, 'PNG')
    fp.seek(0)
    response = make_response(fp.read())
    response.headers.set('Content-Type', 'image/png')
    return response

@bp.route('/2fa/totp/config/enable', methods=['POST'])
@require_login
def totp_config_enable():
    form = TOTPForm()
    if form.validate_on_submit():
        if g.user.totp_secret is not None:
            flash('totp-already-enabled', 'danger')
            return redirect(url_for('.totp_config'))
        totp = pyotp.TOTP(form.totp_secret.data)
        if totp.verify(form.totp.data):
            g.user.totp_secret = form.totp_secret.data
            g.user.generate_totp_recovery_codes()
            g.user.save()
            flash('totp-enable-ok', 'success')
            return redirect(url_for('.totp_config'))
        else:
            flash('totp-enable-invalid-code', 'danger')
            return redirect(url_for('.totp_config'))
    else:
        flash('totp-enable-error', 'danger')
        return redirect(url_for('.totp_config'))

@bp.route('/2fa/totp/config/disable', methods=['POST'])
@require_login
def totp_config_disable():
    g.user.totp_secret = None
    g.user.totp_recovery_codes = None
    flash('totp-disable-ok', 'warning')
    g.user.save()
    return redirect(url_for('.totp_config'))

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()], render_kw={'placeholder': 'Current Password'})
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8, max=128)], render_kw={'placeholder': 'New Password1'})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=8, max=128)], render_kw={'placeholder': 'New Password2'})

@bp.route('/change_password', methods=['GET', 'POST'])
@require_login
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not g.user.check_password(form.current_password.data):
            flash('change-password-invalid-current-password', 'warning')
            return redirect(url_for('.change_password'))
        if form.new_password.data != form.confirm_password.data:
            flash('change-password-passwords-dont-match', 'warning')
            return redirect(url_for('.change_password'))

        if check_password_pwnage(form.new_password.data):
            flash('change-password-new-is-pwned', 'danger')
            return redirect(url_for('.change_password'))

        g.user.set_password(form.new_password.data)
        g.user.save()
        if check_password_pwnage(form.current_password.data):
            flash('change-password-ok-old-is-pwned', 'danger')
        flash('change-password-ok', 'success')
        return redirect(url_for('index'))
    return render_template('change-password.html', form=form)

@bp.route('/webauthn/config')
@require_login
def webauthn_config():
    return 'Not implemented'