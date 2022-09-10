from flask import Blueprint, g, render_template, redirect, url_for, abort, flash
from utils import require_login
from database import *
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired


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

class NameEditForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])

class DescriptionEditForm(FlaskForm):
    description = TextAreaField('Description')

@bp.route('/<slug>')
@require_login
def view(slug):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)
    name_edit_form = NameEditForm(name=project.name)
    description_edit_form = DescriptionEditForm(description=project.description)
    return render_template('dashboard-project-view.html', project=project, name_edit_form=name_edit_form, description_edit_form=description_edit_form)

@bp.route('/api/<slug>/edit-name', methods=['POST'])
@require_login
def api_update_name(slug):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)
    form = NameEditForm()
    if form.validate_on_submit():
        project.name = form.name.data
        project.save()
        flash('project-name-updated', 'success')
    else:
        flash('project-name-update-error', 'danger')
    return redirect(url_for('projects.view', slug=project.slug))

@bp.route('/api/<slug>/edit-description', methods=['POST'])
@require_login
def api_update_description(slug):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)
    form = DescriptionEditForm()
    if form.validate_on_submit():
        project.description = form.description.data
        project.save()
        flash('description-updated', 'success')
        return redirect(url_for('projects.view', slug=project.slug))