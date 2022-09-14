from flask import Blueprint, abort, g, redirect, url_for
from utils import require_login
from database import *
from flask_wtf import FlaskForm

bp = Blueprint('forms', __name__, url_prefix='/forms')

@bp.route('/<slug>')
@require_login
def view(slug):
    form = Form.get_or_none(Form.slug == slug)
    if form is None:
        return abort(404)
    if not form.can_do(g.user, 'view'):
        return abort(403)
    return f'Viewing form {slug}'

class AddFormForm(FlaskForm):
    '''Not actually a form, only a CSRF token is included.'''
    pass

@bp.route('/create/in/<project_slug>', methods=['POST'])
@require_login
def api_create(project_slug):
    project = Project.get_or_none(Project.slug == project_slug)
    if project is None:
        return abort(404)
    if not project.can_do(g.user, 'forms.create'):
        return abort(403)
    form = AddFormForm()
    if form.validate_on_submit():
        form = Form.create(project=project, name='New Untitled Form')
        return redirect(url_for('forms.view', slug=form.slug))
