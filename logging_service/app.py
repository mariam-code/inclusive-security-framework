from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from models import db
from routes import log_bp

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

app.register_blueprint(log_bp)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create the logs database
    app.run(debug=True, port=5002)
