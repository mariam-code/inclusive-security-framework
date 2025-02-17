from flask import Blueprint, request, jsonify
from models import db, Log

log_bp = Blueprint('log_bp', __name__)

@log_bp.route('/logs', methods=['POST'])
def create_log():
    data = request.get_json()
    new_log = Log(event_type=data['event_type'], description=data['description'])
    db.session.add(new_log)
    db.session.commit()
    return jsonify({"message": "Log entry created"}), 201

@log_bp.route('/logs', methods=['GET'])
def get_logs():
    logs = Log.query.all()
    return jsonify([{"event_type": log.event_type, "description": log.description, "timestamp": log.timestamp} for log in logs])
