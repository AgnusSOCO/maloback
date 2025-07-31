"""
Authentication routes for the loan platform
Handles login, registration, and user management
"""

from flask import Blueprint, request, jsonify
from src.models import db
from src.models.user import User
from src.utils.auth import generate_token
from src.utils.helpers import validate_email, sanitize_input, log_action, generate_response, handle_database_error

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST', 'OPTIONS'])
def login():
    """
    User login endpoint
    ✅ FIXED: Handles database schema issues and JWT generation properly
    """
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
            
        email = sanitize_input(data.get('email'))
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password required'}), 400
        
        if not validate_email(email):
            return jsonify({'message': 'Invalid email format'}), 400
        
        # ✅ FIXED: Use safe user lookup with error handling
        user = User.get_by_email(email)
        
        if not user:
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Check password
        if not user.check_password(password):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # ✅ FIXED: Generate token with proper error handling
        try:
            token = generate_token(user)
        except Exception as e:
            print(f"Token generation failed: {e}")
            return jsonify({'message': 'Authentication failed'}), 500
        
        # ✅ FIXED: Get user data with backward compatibility
        user_data = user.to_dict()
        
        # Log successful login
        log_action(user.id, 'login', 'user', user.id, f'Successful login from {request.remote_addr}')
        
        response_data = {
            'token': token,
            'user': user_data
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
def register():
    """User registration endpoint"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        # Validate required fields
        email = sanitize_input(data.get('email'))
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password required'}), 400
        
        if not validate_email(email):
            return jsonify({'message': 'Invalid email format'}), 400
        
        if len(password) < 6:
            return jsonify({'message': 'Password must be at least 6 characters'}), 400
        
        # Check if user exists
        if User.get_by_email(email):
            return jsonify({'message': 'Email already registered'}), 400
        
        # Create new user
        user = User.create_user(
            email=email,
            password=password,
            first_name=sanitize_input(data.get('first_name', '')),
            last_name=sanitize_input(data.get('last_name', '')),
            curp=sanitize_input(data.get('curp', '')),
            phone=sanitize_input(data.get('phone', '')),
            role='applicant',
            status='pending'
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log registration
        log_action(user.id, 'register', 'user', user.id, 'New user registration')
        
        return jsonify({'message': 'User registered successfully'}), 201
    
    except Exception as e:
        print(f"Registration error: {e}")
        db.session.rollback()
        
        error_message, status_code = handle_database_error(e)
        return jsonify({'message': error_message}), status_code

@auth_bp.route('/profile', methods=['GET'])
def get_profile():
    """Get user profile (requires authentication)"""
    from src.utils.auth import token_required
    
    @token_required
    def _get_profile(current_user):
        try:
            user_data = current_user.to_dict()
            return jsonify(user_data), 200
        except Exception as e:
            print(f"Profile error: {e}")
            return jsonify({'message': 'Failed to get profile'}), 500
    
    return _get_profile()

@auth_bp.route('/profile', methods=['PUT'])
def update_profile():
    """Update user profile (requires authentication)"""
    from src.utils.auth import token_required
    
    @token_required
    def _update_profile(current_user):
        try:
            data = request.get_json()
            if not data:
                return jsonify({'message': 'No data provided'}), 400
            
            # Update allowed fields
            if 'first_name' in data:
                current_user.first_name = sanitize_input(data['first_name'])
            if 'last_name' in data:
                current_user.last_name = sanitize_input(data['last_name'])
            if 'phone' in data:
                current_user.phone = sanitize_input(data['phone'])
            if 'curp' in data:
                current_user.curp = sanitize_input(data['curp'])
            
            db.session.commit()
            
            # Log profile update
            log_action(current_user.id, 'profile_update', 'user', current_user.id, 'Profile updated')
            
            user_data = current_user.to_dict()
            return jsonify({'message': 'Profile updated successfully', 'user': user_data}), 200
            
        except Exception as e:
            print(f"Profile update error: {e}")
            db.session.rollback()
            return jsonify({'message': 'Failed to update profile'}), 500
    
    return _update_profile()

