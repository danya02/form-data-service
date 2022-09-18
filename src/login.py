from flask import Blueprint, request, render_template, redirect, url_for, flash, session, g, make_response
from flask_wtf import FlaskForm
from wtforms import PasswordField, HiddenField, EmailField
from wtforms.validators import DataRequired
from database import *
from utils import require_login
import qrcode
import pyotp
import io

bp = Blueprint('login', __name__, url_prefix='/login')

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
    if g.user.webauthn_credential_id is not None:
        return redirect(url_for('.login_2fa_webauthn', next=request.args.get('next', '/')))
    elif g.user.totp_enabled:
        return redirect(url_for('.login_2fa_totp', next=request.args.get('next', '/')))
    else:
        flash('login-error-bug', 'info')

class TOTPForm(FlaskForm):
    totp = PasswordField('TOTP', validators=[DataRequired()], render_kw={'placeholder': '123456'})
    totp_secret = HiddenField('TOTP Secret')  # Only passed in when the user is setting up TOTP, ignored when the user is logging in.

@bp.route('/2fa/totp', methods=['GET', 'POST'])
def login_2fa_totp():
    if session.user is None:
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
    return 'Not implemented'

