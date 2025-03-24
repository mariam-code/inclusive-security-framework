from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity, get_jwt
)
from flask_babel import Babel, gettext as _
from models import db, User
import requests
from functools import wraps
from mfa_helper import generate_otp, send_otp_email, otp_store

user_bp = Blueprint('user_bp', __name__)

#  Role-Based Access Control (RBAC) Decorator
def role_required(required_role):
    """Decorator to restrict access based on user role."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            claims = get_jwt()  # Get JWT claims
            user_role = claims.get("role", "user")  # Default to 'user' if missing

            if user_role != required_role:
                return jsonify({"message": _("Access denied. Insufficient permissions.")}), 403
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

#  Initiate Login and Send OTP
@user_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and send OTP before granting full access."""
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and user.check_password(data['password']):
        otp = generate_otp()
        otp_store[user.username] = otp  # Store OTP against username
        send_otp_email(user.email, otp)
        print(f"Generated OTP for {user.username}: {otp}")  # Debugging line


        # Log successful OTP send
        log_data = {
            "event_type": _("OTP Sent"),
            "description": _("OTP sent to {email}.").format(email=user.email)
        }
        requests.post("http://127.0.0.1:5002/logs", json=log_data)

        return jsonify({
            "message": _("OTP sent to your email"),
            "username": user.username  # The user needs to provide this in the next request
        }), 200
    else:
        # Log failed login attempt
        log_data = {
            "event_type": _("Failed Login"),
            "description": _("Failed login attempt for username: {username}.").format(username=data['username'])
        }
        requests.post("http://127.0.0.1:5002/logs", json=log_data)

        return jsonify({"message": _("Invalid username or password")}), 401

#  OTP Verification (Completes Login)
@user_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP and generate JWT upon success."""
    data = request.get_json()
    username = data.get('username')  # Ensure username is included in request
    entered_otp = data.get('otp')

    user = User.query.filter_by(username=username).first()

    if not user or user.otp != entered_otp:
       return jsonify({"message": _("Invalid or expired OTP")}), 400

    user.otp = None  # Clear the OTP from DB after use
    db.session.commit()


    # Generate a new JWT token with role claims
    access_token = create_access_token(identity=user.username, additional_claims={"role": user.role})

    # Log successful OTP verification
    log_data = {
        "event_type": _("Successful Login"),
        "description": _("User {username} logged in successfully with role {role}.").format(username=user.username, role=user.role)
    }
    requests.post("http://127.0.0.1:5002/logs", json=log_data)

    return jsonify({"message": _("OTP verified. Login successful!"), "access_token": access_token, "role": user.role}), 200

# Register New User (Admin Only)
@user_bp.route('/register', methods=['POST'])
@jwt_required()
@role_required("admin")  # Only admins can register new users
def register():
    """Admin registers a new user with an assigned role."""
    data = request.get_json()

    # Prevent duplicate usernames and emails
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": _("Username already exists")}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"message": _("Email already registered")}), 400

    # Admin assigns a role (defaults to 'user' if not provided)
    role = data.get('role', 'user')

    new_user = User(username=data['username'], email=data['email'], role=role)
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()

    # Log registration
    log_data = {
        "event_type": _("User Registration"),
        "description": _("Admin registered {username} with role {role}.").format(username=new_user.username, role=new_user.role)
    }
    requests.post("http://127.0.0.1:5002/logs", json=log_data)

    return jsonify({"message": _("User registered successfully"), "role": new_user.role}), 201

# Get User Profile (Users Can View Their Own, Admins Can View Any)
@user_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Allow users to retrieve their own profile or admin to retrieve any user."""
    current_user = get_jwt_identity()
    claims = get_jwt()
    user_role = claims.get("role", "user")

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": _("User not found")}), 404

    # Users can only access their own profile unless they are admins
    if current_user != user.username and user_role != "admin":
        return jsonify({"message": _("Access denied")}), 403

    return jsonify({
        "username": user.username,
        "email": user.email,
        "role": user.role
    }), 200

#  Update User Profile (Users Can Edit Their Own, Admins Can Edit Any)
@user_bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """Allow users to update their own profile or admins to update any user."""
    current_user = get_jwt_identity()
    claims = get_jwt()
    user_role = claims.get("role", "user")

    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": _("User not found")}), 404

    # Users can only edit their own profile unless they are admins
    if current_user != user.username and user_role != "admin":
        return jsonify({"message": _("Access denied")}), 403

    data = request.get_json()
    updated_fields = []
    
    if 'username' in data:
        user.username = data['username']
        updated_fields.append('username')
    if 'email' in data:
        user.email = data['email']
        updated_fields.append('email')

    db.session.commit()

    # Log profile update
    log_data = {
        "event_type": _("Profile Update"),
        "description": _("User {username} updated profile: {fields}").format(username=user.username, fields=', '.join(updated_fields))
    }
    requests.post("http://127.0.0.1:5002/logs", json=log_data)

    return jsonify({"message": _("User updated successfully")}), 200

# Admin-Only Route Example
@user_bp.route('/admin', methods=['GET'])
@jwt_required()
@role_required("admin")
def admin_only():
    """Example of a route that only admin users can access."""
    return jsonify({"message": _("Welcome, Admin! You have access to this route.")}), 200

