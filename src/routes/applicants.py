"""
Applicant routes for profile management and bank credential handling
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from src.models.user import db, User, UserRole, Applicant, BankProvider, BankCredential
from src.utils.auth import require_role, get_current_user, log_audit_action, audit_credential_access, ROLE_APPLICANT, ROLE_ADMIN
from src.utils.encryption import encrypt_bank_credentials, decrypt_bank_credentials
import json

applicants_bp = Blueprint('applicants', __name__)

@applicants_bp.route('/profile', methods=['GET'])
@require_role(ROLE_APPLICANT, ROLE_ADMIN)
def get_profile(current_user):
    """Get applicant profile"""
    try:
        if current_user.role == UserRole.APPLICANT:
            applicant = current_user.applicant
        else:
            # Admin accessing specific applicant
            applicant_id = request.args.get('applicant_id')
            if not applicant_id:
                return jsonify({'message': 'applicant_id parameter required for admin access'}), 400
            applicant = Applicant.query.get(applicant_id)
        
        if not applicant:
            return jsonify({'message': 'Applicant profile not found'}), 404
        
        return jsonify({'profile': applicant.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get profile', 'error': str(e)}), 500

@applicants_bp.route('/profile', methods=['PUT'])
@require_role(ROLE_APPLICANT)
def update_profile(current_user):
    """Update applicant profile"""
    try:
        applicant = current_user.applicant
        if not applicant:
            return jsonify({'message': 'Applicant profile not found'}), 404
        
        data = request.get_json()
        
        # Update allowed fields
        if 'first_name' in data:
            applicant.first_name = data['first_name']
        if 'last_name' in data:
            applicant.last_name = data['last_name']
        if 'phone' in data:
            applicant.phone = data['phone']
        if 'curp' in data:
            applicant.curp = data['curp']
        if 'address' in data:
            applicant.address_json = json.dumps(data['address'])
        
        db.session.commit()
        
        # Log profile update
        log_audit_action(
            actor_id=current_user.id,
            action='profile_updated',
            subject_id=applicant.id,
            metadata={'updated_fields': list(data.keys())}
        )
        
        return jsonify({
            'message': 'Profile updated successfully',
            'profile': applicant.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to update profile', 'error': str(e)}), 500

@applicants_bp.route('/banks', methods=['GET'])
def get_banks():
    """Get list of available banks"""
    try:
        banks = BankProvider.query.all()
        return jsonify({
            'banks': [bank.to_dict() for bank in banks]
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get banks', 'error': str(e)}), 500

@applicants_bp.route('/bank-credentials', methods=['POST'])
@require_role(ROLE_APPLICANT)
def add_bank_credentials(current_user):
    """Add bank credentials for applicant"""
    try:
        applicant = current_user.applicant
        if not applicant:
            return jsonify({'message': 'Applicant profile not found'}), 404
        
        data = request.get_json()
        
        # Validate required fields
        if not data.get('provider_id') or not data.get('username') or not data.get('password'):
            return jsonify({'message': 'provider_id, username, and password are required'}), 400
        
        # Check if bank provider exists
        bank_provider = BankProvider.query.get(data['provider_id'])
        if not bank_provider:
            return jsonify({'message': 'Invalid bank provider'}), 400
        
        # Check if credentials already exist for this bank
        existing_credentials = BankCredential.query.filter_by(
            applicant_id=applicant.id,
            provider_id=data['provider_id']
        ).first()
        
        if existing_credentials:
            return jsonify({'message': 'Bank credentials already exist for this provider'}), 409
        
        # Encrypt credentials
        encrypted_data = encrypt_bank_credentials(data['username'], data['password'])
        
        # Create bank credential record
        bank_credential = BankCredential(
            applicant_id=applicant.id,
            provider_id=data['provider_id'],
            username_enc=encrypted_data['username_enc'],
            password_enc=encrypted_data['password_enc'],
            iv=encrypted_data['iv'],
            kek_version=encrypted_data['kek_version']
        )
        
        db.session.add(bank_credential)
        db.session.commit()
        
        # Log credential addition
        log_audit_action(
            actor_id=current_user.id,
            action='bank_credentials_added',
            subject_id=applicant.id,
            metadata={'provider_id': data['provider_id']}
        )
        
        return jsonify({
            'message': 'Bank credentials added successfully',
            'credential': bank_credential.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to add bank credentials', 'error': str(e)}), 500

@applicants_bp.route('/bank-credentials', methods=['GET'])
@require_role(ROLE_APPLICANT, ROLE_ADMIN)
def get_bank_credentials(current_user):
    """Get bank credentials for applicant (metadata only for applicants, full data for admins)"""
    try:
        if current_user.role == UserRole.APPLICANT:
            applicant = current_user.applicant
            include_credentials = False
        else:
            # Admin accessing specific applicant
            applicant_id = request.args.get('applicant_id')
            if not applicant_id:
                return jsonify({'message': 'applicant_id parameter required for admin access'}), 400
            applicant = Applicant.query.get(applicant_id)
            include_credentials = True
        
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        credentials = BankCredential.query.filter_by(applicant_id=applicant.id).all()
        
        result = []
        for credential in credentials:
            cred_data = credential.to_dict(include_credentials=include_credentials)
            # Add bank provider info
            cred_data['provider'] = credential.provider.to_dict()
            result.append(cred_data)
        
        return jsonify({'credentials': result}), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get bank credentials', 'error': str(e)}), 500

@applicants_bp.route('/bank-credentials/<credential_id>', methods=['DELETE'])
@require_role(ROLE_APPLICANT)
def delete_bank_credentials(current_user, credential_id):
    """Delete bank credentials"""
    try:
        applicant = current_user.applicant
        if not applicant:
            return jsonify({'message': 'Applicant profile not found'}), 404
        
        # Find credential belonging to this applicant
        credential = BankCredential.query.filter_by(
            id=credential_id,
            applicant_id=applicant.id
        ).first()
        
        if not credential:
            return jsonify({'message': 'Bank credential not found'}), 404
        
        provider_id = credential.provider_id
        db.session.delete(credential)
        db.session.commit()
        
        # Log credential deletion
        log_audit_action(
            actor_id=current_user.id,
            action='bank_credentials_deleted',
            subject_id=applicant.id,
            metadata={'provider_id': provider_id, 'credential_id': credential_id}
        )
        
        return jsonify({'message': 'Bank credentials deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to delete bank credentials', 'error': str(e)}), 500

@applicants_bp.route('/status', methods=['GET'])
@require_role(ROLE_APPLICANT)
def get_application_status(current_user):
    """Get application status for current applicant"""
    try:
        applicant = current_user.applicant
        if not applicant:
            return jsonify({'message': 'Applicant profile not found'}), 404
        
        # Calculate status based on profile completion
        has_credentials = len(applicant.bank_credentials) > 0
        profile_complete = all([
            applicant.first_name,
            applicant.last_name,
            applicant.phone,
            applicant.curp
        ])
        
        if applicant.contract_signed:
            status = 'approved'
        elif has_credentials and profile_complete:
            status = 'under_review'
        elif profile_complete:
            status = 'pending_bank_info'
        else:
            status = 'incomplete'
        
        return jsonify({
            'status': status,
            'profile_complete': profile_complete,
            'has_bank_credentials': has_credentials,
            'contract_signed': applicant.contract_signed,
            'created_at': applicant.created_at.isoformat() if applicant.created_at else None
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get application status', 'error': str(e)}), 500

