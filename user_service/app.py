from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_babel import Babel
from config import Config
from models import db
from routes import user_bp

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
babel = Babel(app)

app.register_blueprint(user_bp)

# Babel initialization
def get_locale():
    """Automatically selects the best language based on request headers."""
    return request.accept_languages.best_match(app.config.get("LANGUAGES", ["en"]))

with app.app_context():
    babel.init_app(app, locale_selector=get_locale)  #  Babel initialization

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensures tables exist before running
    app.run(debug=True, host="0.0.0.0", port=5005)

