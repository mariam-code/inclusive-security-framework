from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate  # <-- NEW LINE
from config import Config
from models import db
from routes import user_bp

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
migrate = Migrate(app, db)  # <-- NEW LINE
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

app.register_blueprint(user_bp)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensures tables exist before running
    app.run(debug=True, host="0.0.0.0", port=5001)
