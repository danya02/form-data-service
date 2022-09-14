from flask import Blueprint, Flask
from projects import bp as projects_bp
from ingress import bp as ingress_bp
from forms import bp as forms_bp
BLUEPRINTS = [projects_bp, ingress_bp, forms_bp]

def register_blueprints_on_app(app: Flask):
    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)