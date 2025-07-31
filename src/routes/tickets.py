"""
Ticket routes for the loan platform
✅ Full CRUD functionality for ticket system
"""

from flask import Blueprint, request, jsonify
from src.models import db
from src.models.ticket import Ticket
from src.utils.auth import token_required, admin_required
from src.utils.helpers import sanitize_input, log_action, generate_response, handle_database_error

tickets_bp = Blueprint('tickets', __name__)

@tickets_bp.route('/', methods=['GET'])
@token_required
def get_tickets(current_user):
    """
    Get tickets based on user role
    ✅ Admin sees all tickets, users see only their tickets
    """
    try:
        if current_user.role == 'admin':
            # Admin sees all tickets
            tickets = Ticket.get_all()
        else:
            # Users see only their tickets
            tickets = Ticket.get_by_user(current_user.id)
        
        tickets_data = [ticket.to_dict() for ticket in tickets]
        
        return jsonify({'tickets': tickets_data}), 200
        
    except Exception as e:
        print(f"Error getting tickets: {e}")
        return jsonify({'message': 'Error retrieving tickets'}), 500

@tickets_bp.route('/', methods=['POST'])
@token_required
def create_ticket(current_user):
    """
    Create new ticket
    ✅ Full validation and error handling
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        title = sanitize_input(data.get('title'))
        description = sanitize_input(data.get('description'))
        priority = data.get('priority', 'medium')
        category = data.get('category', 'general')
        assigned_to = data.get('assigned_to')
        
        if not title or not description:
            return jsonify({'message': 'Title and description are required'}), 400
        
        # Validate priority
        valid_priorities = ['low', 'medium', 'high', 'urgent']
        if priority not in valid_priorities:
            return jsonify({'message': f'Invalid priority. Must be one of: {", ".join(valid_priorities)}'}), 400
        
        # Validate category
        valid_categories = ['general', 'technical', 'billing', 'support', 'feature']
        if category not in valid_categories:
            return jsonify({'message': f'Invalid category. Must be one of: {", ".join(valid_categories)}'}), 400
        
        # Create ticket
        ticket = Ticket.create_ticket(
            title=title,
            description=description,
            created_by=current_user.id,
            priority=priority,
            category=category,
            assigned_to=assigned_to
        )
        
        db.session.add(ticket)
        db.session.commit()
        
        log_action(current_user.id, 'ticket_create', 'ticket', ticket.id, 
                  f'Created ticket: {title}')
        
        return jsonify({
            'message': 'Ticket created successfully',
            'ticket_id': ticket.id,
            'ticket': ticket.to_dict()
        }), 201
        
    except Exception as e:
        print(f"Error creating ticket: {e}")
        db.session.rollback()
        
        error_message, status_code = handle_database_error(e)
        return jsonify({'message': error_message}), status_code

@tickets_bp.route('/<ticket_id>', methods=['GET'])
@token_required
def get_ticket(current_user, ticket_id):
    """
    Get specific ticket
    ✅ Permission checking (admin or creator)
    """
    try:
        ticket = Ticket.query.filter_by(id=ticket_id).first()
        
        if not ticket:
            return jsonify({'message': 'Ticket not found'}), 404
        
        # Check permissions
        if current_user.role != 'admin' and ticket.created_by != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        ticket_data = ticket.to_dict()
        
        return jsonify(ticket_data), 200
        
    except Exception as e:
        print(f"Error getting ticket: {e}")
        return jsonify({'message': 'Error retrieving ticket'}), 500

@tickets_bp.route('/<ticket_id>', methods=['PUT'])
@token_required
def update_ticket(current_user, ticket_id):
    """
    Update ticket
    ✅ Full field updates with validation
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        ticket = Ticket.query.filter_by(id=ticket_id).first()
        
        if not ticket:
            return jsonify({'message': 'Ticket not found'}), 404
        
        # Check permissions
        if current_user.role != 'admin' and ticket.created_by != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        # Update fields
        if 'title' in data:
            ticket.title = sanitize_input(data['title'])
        
        if 'description' in data:
            ticket.description = sanitize_input(data['description'])
        
        if 'status' in data:
            valid_statuses = ['open', 'in_progress', 'resolved', 'closed']
            if data['status'] in valid_statuses:
                ticket.update_status(data['status'])
            else:
                return jsonify({'message': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400
        
        if 'priority' in data:
            valid_priorities = ['low', 'medium', 'high', 'urgent']
            if data['priority'] in valid_priorities:
                ticket.priority = data['priority']
            else:
                return jsonify({'message': f'Invalid priority. Must be one of: {", ".join(valid_priorities)}'}), 400
        
        if 'category' in data:
            valid_categories = ['general', 'technical', 'billing', 'support', 'feature']
            if data['category'] in valid_categories:
                ticket.category = data['category']
            else:
                return jsonify({'message': f'Invalid category. Must be one of: {", ".join(valid_categories)}'}), 400
        
        if 'assigned_to' in data and current_user.role == 'admin':
            ticket.assign_to(data['assigned_to'])
        
        db.session.commit()
        
        log_action(current_user.id, 'ticket_update', 'ticket', ticket_id, 
                  f'Updated ticket: {ticket.title}')
        
        return jsonify({
            'message': 'Ticket updated successfully',
            'ticket': ticket.to_dict()
        }), 200
        
    except Exception as e:
        print(f"Error updating ticket: {e}")
        db.session.rollback()
        
        error_message, status_code = handle_database_error(e)
        return jsonify({'message': error_message}), status_code

@tickets_bp.route('/<ticket_id>', methods=['DELETE'])
@token_required
def delete_ticket(current_user, ticket_id):
    """
    Delete ticket
    ✅ Permission checking (admin or creator)
    """
    try:
        ticket = Ticket.query.filter_by(id=ticket_id).first()
        
        if not ticket:
            return jsonify({'message': 'Ticket not found'}), 404
        
        # Check permissions (only admin or creator can delete)
        if current_user.role != 'admin' and ticket.created_by != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        ticket_title = ticket.title
        
        db.session.delete(ticket)
        db.session.commit()
        
        log_action(current_user.id, 'ticket_delete', 'ticket', ticket_id, 
                  f'Deleted ticket: {ticket_title}')
        
        return jsonify({'message': 'Ticket deleted successfully'}), 200
        
    except Exception as e:
        print(f"Error deleting ticket: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error deleting ticket'}), 500

@tickets_bp.route('/status/<status>', methods=['GET'])
@token_required
def get_tickets_by_status(current_user, status):
    """Get tickets by status"""
    try:
        valid_statuses = ['open', 'in_progress', 'resolved', 'closed']
        if status not in valid_statuses:
            return jsonify({'message': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400
        
        if current_user.role == 'admin':
            tickets = Ticket.get_by_status(status)
        else:
            # Users see only their tickets with the specified status
            tickets = Ticket.query.filter_by(created_by=current_user.id, status=status).all()
        
        tickets_data = [ticket.to_dict() for ticket in tickets]
        
        return jsonify({'tickets': tickets_data}), 200
        
    except Exception as e:
        print(f"Error getting tickets by status: {e}")
        return jsonify({'message': 'Error retrieving tickets'}), 500

@tickets_bp.route('/stats', methods=['GET'])
@admin_required
def get_ticket_stats(current_user):
    """Get ticket statistics (admin only)"""
    try:
        total_tickets = Ticket.query.count()
        open_tickets = Ticket.query.filter_by(status='open').count()
        in_progress_tickets = Ticket.query.filter_by(status='in_progress').count()
        resolved_tickets = Ticket.query.filter_by(status='resolved').count()
        closed_tickets = Ticket.query.filter_by(status='closed').count()
        
        # Priority statistics
        urgent_tickets = Ticket.query.filter_by(priority='urgent').count()
        high_tickets = Ticket.query.filter_by(priority='high').count()
        
        stats = {
            'total': total_tickets,
            'by_status': {
                'open': open_tickets,
                'in_progress': in_progress_tickets,
                'resolved': resolved_tickets,
                'closed': closed_tickets
            },
            'by_priority': {
                'urgent': urgent_tickets,
                'high': high_tickets
            }
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        print(f"Error getting ticket stats: {e}")
        return jsonify({'message': 'Error retrieving ticket statistics'}), 500

