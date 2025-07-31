"""
Bank-related routes for the loan platform
Handles bank providers and user credentials
"""

from flask import Blueprint, request, jsonify
from src.models import db
from src.models.bank import BankProvider, BankCredential
from src.utils.auth import token_required
from src.utils.helpers import sanitize_input, log_action, generate_response, handle_database_error

banks_bp = Blueprint('banks', __name__)

@banks_bp.route('/banks', methods=['GET'])
def get_banks():
    """Get all bank providers (public endpoint)"""
    try:
        banks = BankProvider.get_all()
        
        banks_data = [bank.to_dict() for bank in banks]
        
        return jsonify({
            'banks': banks_data
        }), 200
        
    except Exception as e:
        print(f"Error getting banks: {e}")
        return jsonify({'message': 'Error retrieving banks'}), 500

@banks_bp.route('/credentials', methods=['GET'])
@token_required
def get_user_credentials(current_user):
    """Get user's bank credentials (passwords hidden for regular users)"""
    try:
        credentials = BankCredential.get_by_user(current_user.id)
        
        # Regular users don't see passwords
        credentials_data = [cred.to_dict(include_password=False) for cred in credentials]
        
        return jsonify(credentials_data), 200
        
    except Exception as e:
        print(f"Error getting credentials: {e}")
        return jsonify({'message': 'Error retrieving credentials'}), 500

@banks_bp.route('/credentials', methods=['POST'])
@token_required
def save_credentials(current_user):
    """Save or update user's bank credentials"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        provider_id = data.get('provider_id')
        username = sanitize_input(data.get('username'))
        password = data.get('password')  # Don't sanitize passwords
        
        if not provider_id or not username or not password:
            return jsonify({'message': 'Provider, username and password required'}), 400
        
        # Verify provider exists
        provider = BankProvider.query.get(provider_id)
        if not provider:
            return jsonify({'message': 'Bank provider not found'}), 404
        
        # Check if credentials already exist for this provider
        existing = BankCredential.get_by_user_and_provider(current_user.id, provider_id)
        
        if existing:
            # Update existing credentials
            existing.username = username
            existing.password = password  # In production, encrypt this
            existing.updated_at = db.func.now()
            
            log_action(current_user.id, 'credentials_update', 'bank_credential', existing.id, 
                      f'Updated credentials for {provider.name}')
        else:
            # Create new credentials
            credential = BankCredential(
                user_id=current_user.id,
                provider_id=provider_id,
                username=username,
                password=password  # In production, encrypt this
            )
            db.session.add(credential)
            
            log_action(current_user.id, 'credentials_create', 'bank_credential', None, 
                      f'Added credentials for {provider.name}')
        
        db.session.commit()
        
        return jsonify({'message': 'Credentials saved successfully'}), 201
        
    except Exception as e:
        print(f"Error saving credentials: {e}")
        db.session.rollback()
        
        error_message, status_code = handle_database_error(e)
        return jsonify({'message': error_message}), status_code

@banks_bp.route('/credentials/<credential_id>', methods=['DELETE'])
@token_required
def delete_credential(current_user, credential_id):
    """Delete user's bank credential"""
    try:
        credential = BankCredential.query.filter_by(
            id=credential_id,
            user_id=current_user.id
        ).first()
        
        if not credential:
            return jsonify({'message': 'Credential not found'}), 404
        
        provider_name = credential.provider.name if credential.provider else 'Unknown'
        
        db.session.delete(credential)
        db.session.commit()
        
        log_action(current_user.id, 'credentials_delete', 'bank_credential', credential_id, 
                  f'Deleted credentials for {provider_name}')
        
        return jsonify({'message': 'Credential deleted successfully'}), 200
        
    except Exception as e:
        print(f"Error deleting credential: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error deleting credential'}), 500

@banks_bp.route('/credentials/<credential_id>', methods=['PUT'])
@token_required
def update_credential(current_user, credential_id):
    """Update user's bank credential"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        credential = BankCredential.query.filter_by(
            id=credential_id,
            user_id=current_user.id
        ).first()
        
        if not credential:
            return jsonify({'message': 'Credential not found'}), 404
        
        # Update fields
        if 'username' in data:
            credential.username = sanitize_input(data['username'])
        if 'password' in data:
            credential.password = data['password']  # Don't sanitize passwords
        
        credential.updated_at = db.func.now()
        db.session.commit()
        
        provider_name = credential.provider.name if credential.provider else 'Unknown'
        log_action(current_user.id, 'credentials_update', 'bank_credential', credential_id, 
                  f'Updated credentials for {provider_name}')
        
        return jsonify({'message': 'Credential updated successfully'}), 200
        
    except Exception as e:
        print(f"Error updating credential: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error updating credential'}), 500

