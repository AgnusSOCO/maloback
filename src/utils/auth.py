"""
Authentication utilities for the loan platform
Handles JWT tokens, password hashing, and role-based access control
"""

import functools
from datetime import datetime, timedelta
from flask import request, jsonify, current_app
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from src.models.user import User, UserRole, AuditLog, db
import json

# JWT Manager instance
jwt = JWTManager()

def init_jwt(app):
    """Initialize JWT with Flask app"""
    app.config['JWT_SECRET_KEY'] = app.config.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    jwt.init_app(app)
    
    @jwt.additional_claims_loader
    def add_claims_to_jwt(identity):
        user = User.query.get(identity)
        if user:
            return {
                'role': user.role.value,
                'email': user.email
            }
        return {}
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({'message': 'Token has expired'}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({'message': 'Invalid token'}), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({'message': 'Authorization token is required'}), 401

def hash_password(password):
    """Hash a password for storing in database"""
    return generate_password_hash(password)

def verify_password(password, password_hash):
    """Verify a password against its hash"""
    return check_password_hash(password_hash, password)

def create_user_token(user):
    """Create JWT token for user"""
    return create_access_token(identity=user.id)

def require_role(*allowed_roles):
    """Decorator to require specific user roles"""
    def decorator(f):
        @functools.wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                return jsonify({'message': 'User not found'}), 404
            
            if current_user.role not in allowed_roles:
                return jsonify({'message': 'Insufficient permissions'}), 403
            
            # Add current user to kwargs for easy access in route handlers
            kwargs['current_user'] = current_user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_audit_action(actor_id, action, subject_id=None, metadata=None):
    """Log an audit action to the database"""
    try:
        audit_log = AuditLog(
            actor_id=actor_id,
            action=action,
            subject_id=subject_id,
            audit_metadata=json.dumps(metadata) if metadata else None
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to log audit action: {e}")
        db.session.rollback()

def audit_credential_access(f):
    """Decorator to audit access to sensitive credential data"""
    @functools.wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_jwt_identity()
        
        # Log the credential access attempt
        log_audit_action(
            actor_id=current_user_id,
            action='credential_access',
            subject_id=kwargs.get('applicant_id'),
            metadata={
                'endpoint': request.endpoint,
                'method': request.method,
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
        )
        
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current authenticated user"""
    try:
        current_user_id = get_jwt_identity()
        return User.query.get(current_user_id) if current_user_id else None
    except:
        return None

# Role constants for easy import
ROLE_ADMIN = UserRole.ADMIN
ROLE_PROMOTER = UserRole.PROMOTER
ROLE_APPLICANT = UserRole.APPLICANT

