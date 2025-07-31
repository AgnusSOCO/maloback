"""
Authentication utilities for the loan platform
Handles JWT tokens, decorators, and authentication logic
"""

import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from src.models.user import User

def generate_token(user):
    """
    Generate JWT token for user with proper error handling
    ✅ FIXED: Uses integer for exp field
    """
    try:
        # ✅ FIXED: Use integer for exp field and proper datetime handling
        expiration_time = datetime.utcnow() + timedelta(hours=24)
        
        token_payload = {
            'user_id': user.id,
            'email': user.email,
            'role': user.role,
            'exp': int(expiration_time.timestamp())  # ✅ Convert to int
        }
        
        token = jwt.encode(token_payload, current_app.config['SECRET_KEY'], algorithm='HS256')
        return token
        
    except Exception as e:
        print(f"Token generation error: {e}")
        raise Exception(f"Failed to generate token: {str(e)}")

def decode_token(token):
    """Decode JWT token"""
    try:
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return data
    except jwt.ExpiredSignatureError:
        raise Exception('Token has expired')
    except jwt.InvalidTokenError:
        raise Exception('Token is invalid')

def get_token_from_request():
    """Extract token from request headers"""
    token = None
    
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        try:
            token = auth_header.split(" ")[1]
        except IndexError:
            raise Exception('Token format invalid')
    
    if not token:
        raise Exception('Token is missing')
    
    return token

def token_required(f):
    """Decorator for routes that require authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token_from_request()
            data = decode_token(token)
            
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
                
        except Exception as e:
            return jsonify({'message': str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator for routes that require admin access"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = get_token_from_request()
            data = decode_token(token)
            
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user or current_user.role != 'admin':
                return jsonify({'message': 'Admin access required'}), 403
                
        except Exception as e:
            return jsonify({'message': str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def optional_auth(f):
    """Decorator for routes with optional authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        current_user = None
        
        try:
            token = get_token_from_request()
            data = decode_token(token)
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            # Authentication is optional, continue without user
            pass
        
        return f(current_user, *args, **kwargs)
    
    return decorated

