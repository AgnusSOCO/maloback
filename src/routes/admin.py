"""
Admin routes for managing applicants, viewing credentials, and handling tickets
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from sqlalchemy import or_, and_
from src.models.user import db, User, UserRole, Applicant, BankCredential, Ticket, TicketComment, TicketStatus, TicketPriority, AuditLog
from src.utils.auth import require_role, get_current_user, log_audit_action, audit_credential_access, ROLE_ADMIN
from src.utils.encryption import decrypt_bank_credentials
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/applicants', methods=['GET'])
@require_role(ROLE_ADMIN)
def get_applicants(current_user):
    """Get list of applicants with filtering and pagination"""
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        search = request.args.get('search', '').strip()
        status_filter = request.args.get('status')
        promoter_id = request.args.get('promoter_id')
        
        # Build query
        query = Applicant.query.join(User)
        
        # Apply filters
        if search:
            query = query.filter(
                or_(
                    Applicant.first_name.ilike(f'%{search}%'),
                    Applicant.last_name.ilike(f'%{search}%'),
                    Applicant.curp.ilike(f'%{search}%'),
                    User.email.ilike(f'%{search}%')
                )
            )
        
        if promoter_id:
            query = query.filter(Applicant.promoter_id == promoter_id)
        
        if status_filter:
            if status_filter == 'approved':
                query = query.filter(Applicant.contract_signed == True)
            elif status_filter == 'pending':
                query = query.filter(Applicant.contract_signed == False)
        
        # Order by creation date (newest first)
        query = query.order_by(Applicant.created_at.desc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        applicants = pagination.items
        
        # Format response
        result = []
        for applicant in applicants:
            applicant_data = applicant.to_dict()
            applicant_data['user'] = applicant.user.to_dict()
            applicant_data['promoter'] = applicant.promoter.to_dict() if applicant.promoter else None
            applicant_data['bank_credentials_count'] = len(applicant.bank_credentials)
            applicant_data['tickets_count'] = len(applicant.tickets)
            result.append(applicant_data)
        
        return jsonify({
            'applicants': result,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get applicants', 'error': str(e)}), 500

@admin_bp.route('/applicants/<applicant_id>', methods=['GET'])
@require_role(ROLE_ADMIN)
@audit_credential_access
def get_applicant_details(current_user, applicant_id):
    """Get detailed applicant information including bank credentials"""
    try:
        applicant = Applicant.query.get(applicant_id)
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        # Get applicant data
        applicant_data = applicant.to_dict()
        applicant_data['user'] = applicant.user.to_dict()
        applicant_data['promoter'] = applicant.promoter.to_dict() if applicant.promoter else None
        
        # Get bank credentials with decrypted data
        credentials = []
        for credential in applicant.bank_credentials:
            cred_data = credential.to_dict()
            cred_data['provider'] = credential.provider.to_dict()
            
            # Decrypt credentials for admin view
            try:
                username, password = decrypt_bank_credentials(
                    credential.username_enc,
                    credential.password_enc,
                    credential.iv
                )
                cred_data['username'] = username
                cred_data['password'] = password
            except Exception as e:
                cred_data['username'] = '[DECRYPTION_ERROR]'
                cred_data['password'] = '[DECRYPTION_ERROR]'
                cred_data['error'] = str(e)
            
            credentials.append(cred_data)
        
        # Get tickets
        tickets = []
        for ticket in applicant.tickets:
            ticket_data = ticket.to_dict()
            ticket_data['creator'] = ticket.creator.to_dict() if ticket.creator else None
            ticket_data['assignee'] = ticket.assignee.to_dict() if ticket.assignee else None
            ticket_data['comments_count'] = len(ticket.comments)
            tickets.append(ticket_data)
        
        return jsonify({
            'applicant': applicant_data,
            'bank_credentials': credentials,
            'tickets': tickets
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get applicant details', 'error': str(e)}), 500

@admin_bp.route('/applicants/<applicant_id>/approve', methods=['POST'])
@require_role(ROLE_ADMIN)
def approve_applicant(current_user, applicant_id):
    """Approve applicant and mark contract as signed"""
    try:
        applicant = Applicant.query.get(applicant_id)
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        data = request.get_json() or {}
        
        applicant.contract_signed = True
        if data.get('contract_scan_url'):
            applicant.contract_scan_url = data['contract_scan_url']
        
        db.session.commit()
        
        # Log approval
        log_audit_action(
            actor_id=current_user.id,
            action='applicant_approved',
            subject_id=applicant_id,
            metadata={'contract_scan_url': data.get('contract_scan_url')}
        )
        
        return jsonify({
            'message': 'Applicant approved successfully',
            'applicant': applicant.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to approve applicant', 'error': str(e)}), 500

@admin_bp.route('/tickets', methods=['GET'])
@require_role(ROLE_ADMIN)
def get_tickets(current_user):
    """Get list of tickets with filtering"""
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        status_filter = request.args.get('status')
        priority_filter = request.args.get('priority')
        applicant_id = request.args.get('applicant_id')
        
        # Build query
        query = Ticket.query
        
        # Apply filters
        if status_filter:
            query = query.filter(Ticket.status == TicketStatus(status_filter))
        
        if priority_filter:
            query = query.filter(Ticket.priority == TicketPriority(priority_filter))
        
        if applicant_id:
            query = query.filter(Ticket.applicant_id == applicant_id)
        
        # Order by priority and creation date
        query = query.order_by(
            Ticket.priority.desc(),
            Ticket.created_at.desc()
        )
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        tickets = pagination.items
        
        # Format response
        result = []
        for ticket in tickets:
            ticket_data = ticket.to_dict()
            ticket_data['applicant'] = ticket.applicant.to_dict() if ticket.applicant else None
            ticket_data['creator'] = ticket.creator.to_dict() if ticket.creator else None
            ticket_data['assignee'] = ticket.assignee.to_dict() if ticket.assignee else None
            ticket_data['comments_count'] = len(ticket.comments)
            result.append(ticket_data)
        
        return jsonify({
            'tickets': result,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get tickets', 'error': str(e)}), 500

@admin_bp.route('/tickets', methods=['POST'])
@require_role(ROLE_ADMIN)
def create_ticket(current_user):
    """Create a new ticket"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('applicant_id') or not data.get('title'):
            return jsonify({'message': 'applicant_id and title are required'}), 400
        
        # Verify applicant exists
        applicant = Applicant.query.get(data['applicant_id'])
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        # Create ticket
        ticket = Ticket(
            applicant_id=data['applicant_id'],
            created_by=current_user.id,
            assigned_to=data.get('assigned_to'),
            title=data['title'],
            priority=TicketPriority(data.get('priority', 'normal')),
            status=TicketStatus.OPEN
        )
        
        db.session.add(ticket)
        db.session.flush()  # Get ticket ID
        
        # Add initial comment if provided
        if data.get('description'):
            comment = TicketComment(
                ticket_id=ticket.id,
                author_id=current_user.id,
                body=data['description']
            )
            db.session.add(comment)
        
        db.session.commit()
        
        # Log ticket creation
        log_audit_action(
            actor_id=current_user.id,
            action='ticket_created',
            subject_id=ticket.id,
            metadata={'applicant_id': data['applicant_id'], 'title': data['title']}
        )
        
        return jsonify({
            'message': 'Ticket created successfully',
            'ticket': ticket.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to create ticket', 'error': str(e)}), 500

@admin_bp.route('/tickets/<ticket_id>/comments', methods=['POST'])
@require_role(ROLE_ADMIN)
def add_ticket_comment(current_user, ticket_id):
    """Add comment to ticket"""
    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({'message': 'Ticket not found'}), 404
        
        data = request.get_json()
        if not data.get('body'):
            return jsonify({'message': 'Comment body is required'}), 400
        
        comment = TicketComment(
            ticket_id=ticket_id,
            author_id=current_user.id,
            body=data['body']
        )
        
        db.session.add(comment)
        db.session.commit()
        
        # Log comment addition
        log_audit_action(
            actor_id=current_user.id,
            action='ticket_comment_added',
            subject_id=ticket_id,
            metadata={'comment_id': comment.id}
        )
        
        return jsonify({
            'message': 'Comment added successfully',
            'comment': comment.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to add comment', 'error': str(e)}), 500

@admin_bp.route('/audit-logs', methods=['GET'])
@require_role(ROLE_ADMIN)
def get_audit_logs(current_user):
    """Get audit logs with filtering"""
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        action_filter = request.args.get('action')
        actor_id = request.args.get('actor_id')
        
        # Build query
        query = AuditLog.query
        
        # Apply filters
        if action_filter:
            query = query.filter(AuditLog.action.ilike(f'%{action_filter}%'))
        
        if actor_id:
            query = query.filter(AuditLog.actor_id == actor_id)
        
        # Order by creation date (newest first)
        query = query.order_by(AuditLog.created_at.desc())
        
        # Paginate
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        logs = pagination.items
        
        # Format response
        result = []
        for log in logs:
            log_data = log.to_dict()
            log_data['actor'] = log.actor.to_dict() if log.actor else None
            result.append(log_data)
        
        return jsonify({
            'audit_logs': result,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get audit logs', 'error': str(e)}), 500

