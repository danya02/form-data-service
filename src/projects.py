from flask import Blueprint, g, render_template, redirect, url_for
from utils import require_login
from database import *
from flask_wtf import FlaskForm


bp = Blueprint('projects', __name__, url_prefix='/projects')

class CreateProjectForm(FlaskForm):
    '''Not actually a form, only a CSRF token is included.'''
    pass

@bp.route('/')
@require_login
def index():
    owned_projects = Project.select().where(Project.owner == g.user)
    member_projects = Project.select().join(ProjectUser).where(ProjectUser.user == g.user).where(ProjectUser.project.not_in(owned_projects))
    create_form = CreateProjectForm()

    return render_template('dashboard-main.html', owned_projects=owned_projects, member_projects=member_projects, create_form=create_form)


@bp.route('/create', methods=['POST'])
@require_login
def create():
    # N.B. There must never be a project called "create".
    form = CreateProjectForm()
    if form.validate_on_submit():
        project = Project.create(owner=g.user, name='New Untitled Project')
        return redirect(url_for('projects.view', slug=project.slug))

@bp.route('/<slug>')
@require_login
def view(slug):
    return f'Project {slug}'
