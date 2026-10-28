from flask import Flask, render_template
from extensions import db, login_manager
import os

def create_app():
    # LAB REQUIREMENT: Key Generation on Startup
    from crypto_utils import generate_keys
    generate_keys()

    app = Flask(__name__)
    
    # Config
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')
    
    # Handle Render's DATABASE_URL (often postgres:// but needs postgresql://)
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///secure_cert.db')
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Register Blueprints
    from auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from certificates import certificates as cert_blueprint
    app.register_blueprint(cert_blueprint)

    @app.route('/')
    def index():
        return render_template('index.html')

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        # Import models so they are registered with SQLAlchemy
        import models
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
