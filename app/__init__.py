import os
from flask import Flask
from config import Config
from .extensions import db, login_manager
from .routes.auth import auth_bp
from .routes.main import main_bp
from .routes.api import api_bp
from .routes.reports import reports_bp
from .services.seed_service import seed_database
from .routes.admin import admin_bp

def create_app(config_class=Config):
    
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    app = Flask(
        __name__,
        instance_relative_config=False,
        template_folder=os.path.join(BASE_DIR, '../templates'),
        static_folder=os.path.join(BASE_DIR, '../static')
    )

    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    # ✅ Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)

    # ✅ DB + seed
    with app.app_context():
        db.create_all()
        seed_database()

    # 🔍 Debug (remove later)
    print("Template path:", app.template_folder)

    return app