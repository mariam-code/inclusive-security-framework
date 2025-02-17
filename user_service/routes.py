from flask import Blueprint, request, jsonify
from models import db, User
import requests


user_bp = Blueprint('user_bp', __name__)

@user_bp.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Email already registered"}), 400
    
    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()

        # Log the registration event
    log_data = {
        "event_type": "User Registration",
        "description": f"User {new_user.username} registered."
    }
    requests.post("http://127.0.0.1:5002/logs", json=log_data)
    
    return jsonify({"message": "User registered successfully"}), 201

@user_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Retrieve a user by ID."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    return jsonify({"username": user.username, "email": user.email}), 200

@user_bp.route('/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Update a user's details."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.get_json()
    if 'username' in data:
        user.username = data['username']
    if 'email' in data:
        user.email = data['email']
    db.session.commit()

    # Log the update
    log_data = {
        "event_type": "Profile Update",
        "description": f"User {user.id} updated profile: {', '.join(updated_fields)}"
    }
    requests.post("http://127.0.0.1:5002/logs", json=log_data)

    return jsonify({"message": "User updated successfully"}), 200

@user_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and log login attempts."""
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']):
        # Successful login
        log_data = {
            "event_type": "Successful Login",
            "description": f"User {user.username} logged in successfully."
        }
        requests.post("http://127.0.0.1:5002/logs", json=log_data)

        return jsonify({"message": "Login successful"}), 200
    else:
        # Failed login attempt
        log_data = {
            "event_type": "Failed Login",
            "description": f"Failed login attempt for username: {data['username']}."
        }
        requests.post("http://127.0.0.1:5002/logs", json=log_data)

        return jsonify({"message": "Invalid username or password"}), 401
