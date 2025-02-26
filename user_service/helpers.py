import jwt
from flask import request, jsonify
from functools import wraps
from config import SECRET_KEY

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token:
                return jsonify({"message": "Missing token"}), 403

            try:
                token = token.split("Bearer ")[1]
                decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                if decoded_token.get("role") != required_role:
                    return jsonify({"message": "Unauthorized"}), 403
            except jwt.ExpiredSignatureError:
                return jsonify({"message": "Token expired"}), 403
            except jwt.InvalidTokenError:
                return jsonify({"message": "Invalid token"}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
