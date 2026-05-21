import os
from flask import Flask
from web.routes import register_blueprints


def create_app():
    template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    public_dir = os.path.join(os.path.dirname(__file__), "..", "public")
    app = Flask(
        __name__,
        template_folder=os.path.abspath(template_dir),
        static_folder=os.path.abspath(public_dir),
        static_url_path="/public",
    )
    register_blueprints(app)
    return app
