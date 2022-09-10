from flask import Blueprint, Flask
from projects import bp as projects_bp
BLUEPRINTS = [projects_bp]

def register_blueprints_on_app(app: Flask):
    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)