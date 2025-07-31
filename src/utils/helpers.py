"""
Helper utilities for the loan platform
"""

from flask import request
from src.models import db
from src.models.audit import AuditLog

def get_client_ip():
    """Get client IP address"""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

def get_user_agent():
    """Get user agent string"""
    return request.headers.get('User-Agent', '')

def log_action(user_id, action, resource_type, resource_id=None, details=None):
    """Log user action for audit trail"""
    try:
        audit_log = AuditLog.log_action(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=get_client_ip(),
            user_agent=get_user_agent()
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
    except Exception as e:
        print(f"Failed to log action: {e}")
        # Don't fail the main operation if logging fails
        pass

def validate_email(email):
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_curp(curp):
    """Basic CURP validation for Mexican identification"""
    if not curp or len(curp) != 18:
        return False
    
    # Basic pattern check (simplified)
    import re
    pattern = r'^[A-Z]{4}[0-9]{6}[HM][A-Z]{5}[0-9A-Z][0-9]$'
    return re.match(pattern, curp.upper()) is not None

def sanitize_input(text, max_length=None):
    """Sanitize user input"""
    if not text:
        return text
    
    # Remove potentially dangerous characters
    text = text.strip()
    
    if max_length:
        text = text[:max_length]
    
    return text

def format_phone(phone):
    """Format phone number"""
    if not phone:
        return phone
    
    # Remove all non-digit characters
    digits = ''.join(filter(str.isdigit, phone))
    
    # Format Mexican phone numbers
    if len(digits) == 10:
        return f"+52 {digits[:2]} {digits[2:6]} {digits[6:]}"
    elif len(digits) == 12 and digits.startswith('52'):
        return f"+{digits[:2]} {digits[2:4]} {digits[4:8]} {digits[8:]}"
    
    return phone

def generate_response(data=None, message=None, status_code=200):
    """Generate standardized API response"""
    response = {}
    
    if message:
        response['message'] = message
    
    if data is not None:
        if isinstance(data, dict):
            response.update(data)
        else:
            response['data'] = data
    
    return response, status_code

def handle_database_error(error):
    """Handle database errors gracefully"""
    error_message = str(error)
    
    if 'duplicate key' in error_message.lower():
        return "This record already exists", 409
    elif 'foreign key' in error_message.lower():
        return "Referenced record not found", 400
    elif 'not null' in error_message.lower():
        return "Required field is missing", 400
    else:
        print(f"Database error: {error}")
        return "Database operation failed", 500

