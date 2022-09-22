from flask import Blueprint, g, render_template, redirect, url_for, abort, flash
from utils import require_login
from database import *
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, EmailField
from wtforms.validators import DataRequired
from forms import AddFormForm


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
        AuditLogEntry.log('project_create',
            project=project
        )
        return redirect(url_for('projects.view', slug=project.slug))
        return redirect(url_for('projects.view', slug=project.slug))

class NameEditForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])

class DescriptionEditForm(FlaskForm):
    description = TextAreaField('Description')

class LeaveProjectForm(FlaskForm):
    '''Not actually a form, only a CSRF token is included.'''
    pass

class DeleteProjectForm(FlaskForm):
    '''Not actually a form, only a CSRF token is included.'''
    pass


@bp.route('/<slug>')
@require_login
def view(slug):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)

    project_members = list(map(lambda x: x.user, ProjectUser.select().join(User).where(ProjectUser.project == project)))

    name_edit_form = NameEditForm(name=project.name)
    description_edit_form = DescriptionEditForm(description=project.description)
    leave_project_form = LeaveProjectForm()
    delete_project_form = DeleteProjectForm()
    add_member_form = AddMemberForm()
    remove_member_form = RemoveMemberForm()
    add_form_form = AddFormForm()
    forms = Form.select().where(Form.project == project)
    return render_template('dashboard-project-view.html', project=project, name_edit_form=name_edit_form, description_edit_form=description_edit_form,
                           leave_form=leave_project_form, delete_form=delete_project_form,
                           add_member_form=add_member_form, remove_member_form=remove_member_form,
                           project_members=project_members, add_form_form=add_form_form, forms=forms)


@bp.route('/api/<slug>/edit-name', methods=['POST'])
@require_login
def api_update_name(slug):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)
    form = NameEditForm()
    if form.validate_on_submit():
        old_name = project.name
        project.save()
        AuditLogEntry.log('project_edit_name',
            project=project,
            data={'new_name': project.name}
        )
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
        AuditLogEntry.log('project_edit_description',
            project=project,
            data={'new_description': project.description})
        return redirect(url_for('projects.view', slug=project.slug))

@bp.route('/api/<slug>/leave', methods=['POST'])
@require_login
def api_leave_project(slug):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)
    form = LeaveProjectForm()
    if form.validate_on_submit():
        ProjectUser.delete().where(ProjectUser.project == project, ProjectUser.user == g.user).execute()
        flash('left-project', 'success')
        AuditLogEntry.log('project_leave',
            project=project
        )
    return redirect(url_for('projects.index'))

@bp.route('/api/<slug>/delete', methods=['POST'])
@require_login
def api_delete_project(slug):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)
    form = DeleteProjectForm()
    if form.validate_on_submit():
        AuditLogEntry.log(
            'project_delete',
            project=None, # Because the project is now gone, so we cannot reference it.
            data={
                'project_slug': project.slug,
                'project_name': project.name,
                'project_description': project.description,
                'form_count': project.form_count,
                'member_count': project.member_count,
                'total_record_count': project.total_record_count
                }
        )
        ProjectUser.delete().where(ProjectUser.project == project).execute()
        project.delete_instance()
        flash('project-deleted', 'success')
    return redirect(url_for('projects.index'))

class AddMemberForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])

@bp.route('/api/<slug>/add_member', methods=['POST'])
@require_login
def api_add_member(slug):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)
    form = AddMemberForm()
    if form.validate_on_submit():
        user = User.get_or_none(User.email == form.email.data)
        if g.user != project.owner:
            flash('add-not-owner', 'danger')
        elif user is None:
            flash('add-user-not-found', 'danger')
        else:
            try:
                ProjectUser.create(project=project, user=user)
                flash('add-ok', 'success')
                AuditLogEntry.log('project_add_member',
                    project=project,
                    data={'new_member_id': user.id,
                          'new_member_email': user.email}
                )
            except pw.IntegrityError:
                flash('add-user-already-member', 'danger')
    return redirect(url_for('projects.view', slug=project.slug))

class RemoveMemberForm(FlaskForm):
    '''Not actually a form, only a CSRF token is included.'''
    pass

@bp.route('/api/<slug>/remove_member/<user_id>', methods=['POST'])
@require_login
def api_remove_member(slug, user_id):
    project = Project.get_or_none(Project.slug == slug)
    if project is None:
        return abort(404)
    if g.user != project.owner:
        flash('remove-not-owner', 'danger')
    user = User.get_or_none(User.id == user_id)
    if user is None:
        return abort(404)
    else:
        form = RemoveMemberForm()
        if form.validate_on_submit():
            ProjectUser.delete().where(ProjectUser.project == project, ProjectUser.user == user).execute()
            flash('remove-ok', 'success')
            AuditLogEntry.log('project_remove_member',
                project=project,
                data={'removed_member_id': user.id,
                        'removed_member_email': user.email}
            )
    return redirect(url_for('projects.view', slug=project.slug))