from flask import Blueprint, request, jsonify, abort, redirect
import json

from database import *

bp = Blueprint('ingress', __name__, url_prefix='/ingress')

@bp.route('/form/<slug>', methods=['POST'])
def form_submit(slug):
    form = Form.get_or_none(Form.slug == slug)
    if form is None:
        abort(404)
    
    record_data = {}
    for field in form.fields:
        if field['required'] and field['name'] not in request.form:
            abort(400)
        record_data[field['name']] = request.form.get(field['name'])
    
    if not form.config.get('store_only_fields', False):
        record_data.update(request.form)
    
    record_metadata = {}
    if form.config.get('store_ip', False):
        record_metadata['ip'] = request.remote_addr
    if form.config.get('store_headers', False):
        record_metadata['headers'] = dict(request.headers)
    
    json_length = len(json.dumps(record_data))
    if json_length > form.config.get('max_data_size', 1*1024*1024):
        abort(413)

    record = FormRecord.create(
        form=form,
        data=record_data,
        metadata=record_metadata,
        unread=True
    )

    if form.config.get('redirect', False):
        return redirect(form.config['redirect'])
    else:
        return jsonify({
            'success': True,
            'record_id': record.id,
            'record_data': record.data,
            'form_data': request.form
            })