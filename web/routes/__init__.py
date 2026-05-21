from .dashboard import dashboard_bp
from .intelligence import intelligence_bp
from .health import health_bp
from .pages import pages_bp
from .assets import assets_bp


def register_blueprints(app):
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(intelligence_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(pages_bp)
    app.register_blueprint(assets_bp)
