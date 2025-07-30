"""
Authentication routes for login, registration, and token management
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models.user import db, User, UserRole, Applicant, Promoter
from src.utils.auth import hash_password, verify_password, create_user_token, get_current_user, log_audit_action
import json

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400
        
        email = data['email'].lower().strip()
        password = data['password']
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if not user or not verify_password(password, user.password_hash):
            # Log failed login attempt
            log_audit_action(
                actor_id=user.id if user else None,
                action='login_failed',
                metadata={'email': email, 'ip_address': request.remote_addr}
            )
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Create JWT token
        token = create_user_token(user)
        
        # Log successful login
        log_audit_action(
            actor_id=user.id,
            action='login_success',
            metadata={'ip_address': request.remote_addr}
        )
        
        # Get user profile data based on role
        profile_data = user.to_dict()
        if user.role == UserRole.APPLICANT and user.applicant:
            profile_data['profile'] = user.applicant.to_dict()
        elif user.role == UserRole.PROMOTER and user.promoter:
            profile_data['profile'] = user.promoter.to_dict()
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': profile_data
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@auth_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint for applicants"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'first_name', 'last_name', 'phone']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'message': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'User with this email already exists'}), 409
        
        # Create new user
        user = User(
            email=email,
            password_hash=hash_password(data['password']),
            role=UserRole.APPLICANT
        )
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        # Create applicant profile
        applicant = Applicant(
            id=user.id,
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone=data['phone'],
            curp=data.get('curp'),
            address_json=json.dumps(data.get('address', {})),
            promoter_id=data.get('promoter_id')
        )
        db.session.add(applicant)
        db.session.commit()
        
        # Create JWT token
        token = create_user_token(user)
        
        # Log registration
        log_audit_action(
            actor_id=user.id,
            action='user_registered',
            metadata={'role': 'applicant', 'ip_address': request.remote_addr}
        )
        
        return jsonify({
            'message': 'Registration successful',
            'token': token,
            'user': {
                **user.to_dict(),
                'profile': applicant.to_dict()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500

@auth_bp.route('/register-promoter', methods=['POST'])
def register_promoter():
    """Promoter registration endpoint (admin only)"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'name', 'phone']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'message': f'{field} is required'}), 400
        
        email = data['email'].lower().strip()
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'User with this email already exists'}), 409
        
        # Create new user
        user = User(
            email=email,
            password_hash=hash_password(data['password']),
            role=UserRole.PROMOTER
        )
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        # Create promoter profile
        promoter = Promoter(
            id=user.id,
            name=data['name'],
            phone=data['phone']
        )
        db.session.add(promoter)
        db.session.commit()
        
        # Log registration
        log_audit_action(
            actor_id=user.id,
            action='promoter_registered',
            metadata={'ip_address': request.remote_addr}
        )
        
        return jsonify({
            'message': 'Promoter registration successful',
            'user': {
                **user.to_dict(),
                'profile': promoter.to_dict()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Promoter registration failed', 'error': str(e)}), 500

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user_info():
    """Get current user information"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'message': 'User not found'}), 404
        
        # Get user profile data based on role
        profile_data = current_user.to_dict()
        if current_user.role == UserRole.APPLICANT and current_user.applicant:
            profile_data['profile'] = current_user.applicant.to_dict()
        elif current_user.role == UserRole.PROMOTER and current_user.promoter:
            profile_data['profile'] = current_user.promoter.to_dict()
        
        return jsonify({'user': profile_data}), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get user info', 'error': str(e)}), 500

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user password"""
    try:
        current_user = get_current_user()
        if not current_user:
            return jsonify({'message': 'User not found'}), 404
        
        data = request.get_json()
        
        if not data.get('current_password') or not data.get('new_password'):
            return jsonify({'message': 'Current password and new password are required'}), 400
        
        # Verify current password
        if not verify_password(data['current_password'], current_user.password_hash):
            return jsonify({'message': 'Current password is incorrect'}), 401
        
        # Update password
        current_user.password_hash = hash_password(data['new_password'])
        db.session.commit()
        
        # Log password change
        log_audit_action(
            actor_id=current_user.id,
            action='password_changed',
            metadata={'ip_address': request.remote_addr}
        )
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to change password', 'error': str(e)}), 500

