from asyncore import write
from flask import Blueprint, abort, g, redirect, url_for, flash, request, render_template, Response
from utils import require_login
from database import *
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired
import json
import io
import csv

bp = Blueprint('forms', __name__, url_prefix='/forms')

class NameEditForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])

class DeleteForm(FlaskForm):
    '''Not actually a form, only a CSRF token is included.'''
    pass

@bp.route('/<slug>')
@require_login
def view(slug):
    form = Form.get_or_none(Form.slug == slug)
    if form is None:
        return abort(404)
    if not form.can_do(g.user, 'view'):
        return abort(403)

    name_edit_form = NameEditForm(name=form.name)
    delete_form = DeleteForm()

    # TODO: Pagination
    records_section = FormRecord.select().where(FormRecord.form == form).order_by(FormRecord.created_at.desc())

    return render_template('form-view.html', form=form, name_edit_form=name_edit_form,
                            delete_form=delete_form, records_section=records_section,
                            into_json=lambda x: json.dumps(x, indent=4))

@bp.route('/<slug>/export.csv')
@require_login
def export_csv(slug):
    form = Form.get_or_none(Form.slug == slug)
    if form is None:
        return abort(404)
    if not form.can_do(g.user, 'view'):
        return abort(403)

    def response_generator():
        def write_rows(rows):
            f = io.StringIO()
            writer = csv.writer(f)
            writer.writerows(rows)
            return f.getvalue().strip() + '\n'
        fields = ['Date','UNIX Timestamp','Unread?']

        for field in form.fields:
            fields.append(field['name'])
        fields.append('Raw JSON Data')
        fields.append('JSON Metadata')

        yield write_rows([fields])

        page = 1
        while True:
            records = FormRecord.select().where(FormRecord.form == form).order_by(FormRecord.created_at.desc()).paginate(page, 100)
            datas = []
            for record in records:
                data = [record.created_at.strftime('%Y-%m-%d %H:%M:%S'), str(record.created_at.timestamp()), str(int(record.unread))]
                for field in form.fields:
                    data.append(record.data.get(field['name'], ''))
                data.append(json.dumps(record.data))
                data.append(json.dumps(record.metadata))
                datas.append(data)

            if not datas:
                break
            yield write_rows(datas)
            page += 1
    return Response(response_generator(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{form.name} export.csv"'})


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


@bp.route('/<slug>/api/set_name', methods=['POST'])
@require_login
def api_update_name(slug):
    form = Form.get_or_none(Form.slug == slug)
    if form is None:
        return abort(404)
    if not form.can_do(g.user, 'forms.edit'):
        return abort(403)
    name_edit_form = NameEditForm()
    if name_edit_form.validate_on_submit():
        form.name = name_edit_form.name.data
        form.save()
        flash('form-name-set', 'success')
        return redirect(url_for('forms.view', slug=form.slug))


@bp.route('/<slug>/api/update_fields', methods=['POST'])
@require_login
def api_update_fields(slug):
    form = Form.get_or_none(Form.slug == slug)
    if form is None:
        return abort(404)
    if not form.can_do(g.user, 'forms.edit'):
        return abort(403)

    def bail():
        flash('form-fields-invalid-generic', 'danger')
        abort(400)

    fields = request.get_json()
    if fields is None: bail()
    if not isinstance(fields, dict): bail()
    if not 'new' in fields: bail()
    if not 'old' in fields: bail()
    if not isinstance(fields['new'], list): bail()
    if not isinstance(fields['old'], list): bail()
    
    if fields['old'] != form.fields:
        flash('form-fields-already-edited', 'danger')
        abort(409)

    new_fields = fields['new']

    seen_fields = set()
    for field in new_fields:
        if not isinstance(field, dict): bail()
        if 'name' not in field: bail()
        if 'required' not in field: bail()
        if field['required'] not in (True, False): bail()
        if field['name'] in seen_fields:
            flash('form-fields-invalid-duplicate', 'danger')
            return abort(400)
        seen_fields.add(field['name'])
    
    form.fields = new_fields
    form.save()
    flash('form-fields-set', 'success')
    return 'ok'  # This is a JS API endpoint, so we don't redirect.



@bp.route('/<slug>/api/delete', methods=['POST'])
@require_login
def api_delete_form(slug):
    form = Form.get_or_none(Form.slug == slug)
    if form is None:
        return abort(404)
    if not form.can_do(g.user, 'forms.delete'):
        return abort(403)
    delete_form = DeleteForm()
    if delete_form.validate_on_submit():
        form.delete_instance()
        flash('form-deleted', 'success')
        return redirect(url_for('projects.view', slug=form.project.slug))

@bp.route('/<slug>/api/toggle_read/<record_id>', methods=['POST'])
@require_login
def api_toggle_view(slug, record_id):
    form = Form.get_or_none(Form.slug == slug)
    if form is None:
        return abort(404)
    if not form.can_do(g.user, 'forms.view'):
        return abort(403)
    record = FormRecord.get_or_none(FormRecord.id == record_id)
    if record is None:
        return abort(404)
    if record.form != form:
        return abort(403)
    
    record.unread = not record.unread
    record.save()
    return 'true' if record.unread else 'false'