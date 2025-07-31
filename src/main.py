"""
Updated main.py with fixed database persistence for bank credentials
Replace your current main.py with this version
"""

import os
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///loan_platform.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager(app)

# COMPREHENSIVE CORS configuration for Vercel
CORS(app,
    origins=[
        "http://localhost:3000",      # React dev server
        "http://localhost:5173",      # Vite dev server
        "https://*.vercel.app",       # All Vercel subdomains
        "https://vercel.app",         # Vercel main domain
        "https://malofront.vercel.app", # Your specific domain
        "*"                           # Allow all origins (for testing)
    ],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    supports_credentials=True
)

# Add explicit OPTIONS handler for preflight requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response

# Define models
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='applicant')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Personal information
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    curp = db.Column(db.String(25), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_approved = db.Column(db.Boolean, default=False)

class BankProvider(db.Model):
    __tablename__ = 'bank_providers'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    logo_url = db.Column(db.String(500))

class BankCredential(db.Model):
    __tablename__ = 'bank_credentials'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    provider_id = db.Column(db.String(36), db.ForeignKey('bank_providers.id'), nullable=False)
    encrypted_username = db.Column(db.Text, nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='bank_credentials')
    provider = db.relationship('BankProvider', backref='credentials')

# Initialize database
db.init_app(app)

with app.app_context():
    # Create all tables
    db.create_all()
    print("✅ Database tables created")
    
    # Seed bank providers if they don't exist
    if BankProvider.query.count() == 0:
        banks = [
            {'name': 'BBVA México', 'code': 'bbva'},
            {'name': 'Santander México', 'code': 'santander'},
            {'name': 'Banamex', 'code': 'banamex'},
            {'name': 'Banorte', 'code': 'banorte'},
            {'name': 'HSBC México', 'code': 'hsbc'},
            {'name': 'Banco Azteca', 'code': 'azteca'}
        ]
        
        for bank_data in banks:
            bank = BankProvider(
                id=str(uuid.uuid4()),
                name=bank_data['name'],
                code=bank_data['code']
            )
            db.session.add(bank)
        
        db.session.commit()
        print("✅ Bank providers seeded")
    
    # Create admin user if it doesn't exist
    if not User.query.filter_by(email='admin@loanplatform.com').first():
        admin_user = User(
            id=str(uuid.uuid4()),
            email='admin@loanplatform.com',
            password_hash=generate_password_hash('admin123'),
            first_name='Admin',
            last_name='User',
            curp='ADMIN123456HDFRRL01',
            role='admin',
            is_active=True,
            is_approved=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print("✅ Admin user created")

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Loan Platform API is running',
        'database': 'connected',
        'cors': 'enabled'
    })

# Test endpoint
@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({
        'message': 'API is working!',
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'database_url': 'configured' if app.config['SQLALCHEMY_DATABASE_URI'] else 'not configured',
        'cors_origins': 'all_allowed'
    })

# Authentication endpoints
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
        
        if user and check_password_hash(user.password_hash, password):
            token = create_access_token(identity=user.id)
            return jsonify({
                'token': token,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'role': user.role,
                    'name': f"{user.first_name} {user.last_name}"
                }
            })
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@app.route('/api/auth/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'first_name', 'last_name', 'curp']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'message': f'{field} is required'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already registered'}), 400
        
        # Create new user
        user = User(
            id=str(uuid.uuid4()),
            email=data['email'],
            password_hash=generate_password_hash(data['password']),
            first_name=data['first_name'],
            last_name=data['last_name'],
            curp=data['curp'],
            role=data.get('role', 'applicant'),
            phone=data.get('phone'),
            is_active=True
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Create token
        token = create_access_token(identity=user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': user.role,
                'name': f"{user.first_name} {user.last_name}"
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500

# Bank endpoints
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
        return jsonify({'message': 'Failed to fetch banks', 'error': str(e)}), 500

# Bank Credentials endpoints
@app.route('/api/applicants/credentials', methods=['GET', 'OPTIONS'])
def get_user_credentials():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        # For now, get user from JWT token (simplified for testing)
        # In production, you'd decode the JWT token to get user_id
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Authorization header required'}), 401
        
        # For testing, we'll use the first user (juan@socopwa.com)
        user = User.query.filter_by(email='juan@socopwa.com').first()
        if not user:
            return jsonify({'credentials': []})
        
        credentials = BankCredential.query.filter_by(user_id=user.id).all()
        
        return jsonify({
            'credentials': [{
                'id': cred.id,
                'provider_id': cred.provider_id,
                'username': cred.encrypted_username,  # In production, decrypt this
                'created_at': cred.created_at.isoformat(),
                'provider_name': cred.provider.name if cred.provider else 'Unknown'
            } for cred in credentials]
        })
        
    except Exception as e:
        return jsonify({'message': 'Failed to fetch credentials', 'error': str(e)}), 500

@app.route('/api/applicants/credentials', methods=['POST', 'OPTIONS'])
def save_credentials():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        provider_id = data.get('provider_id')
        username = data.get('username')
        password = data.get('password')
        
        if not provider_id or not username or not password:
            return jsonify({'message': 'Provider ID, username, and password are required'}), 400
        
        # For testing, we'll use the first user (juan@socopwa.com)
        user = User.query.filter_by(email='juan@socopwa.com').first()
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        # Check if provider exists
        provider = BankProvider.query.get(provider_id)
        if not provider:
            return jsonify({'message': 'Bank provider not found'}), 404
        
        # Check if credentials already exist for this user and provider
        existing = BankCredential.query.filter_by(
            user_id=user.id, 
            provider_id=provider_id
        ).first()
        
        if existing:
            # Update existing credentials
            existing.encrypted_username = username  # In production, encrypt this
            existing.encrypted_password = password  # In production, encrypt this
            credential_id = existing.id
        else:
            # Create new credentials
            credential = BankCredential(
                id=str(uuid.uuid4()),
                user_id=user.id,
                provider_id=provider_id,
                encrypted_username=username,  # In production, encrypt this
                encrypted_password=password   # In production, encrypt this
            )
            db.session.add(credential)
            credential_id = credential.id
        
        # CRITICAL: Commit the transaction
        db.session.commit()
        
        return jsonify({
            'credential_id': credential_id,
            'message': 'Credentials saved successfully'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to save credentials', 'error': str(e)}), 500

@app.route('/api/applicants/credentials/<credential_id>', methods=['DELETE', 'OPTIONS'])
def delete_credentials(credential_id):
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        credential = BankCredential.query.get(credential_id)
        if not credential:
            return jsonify({'message': 'Credentials not found'}), 404
        
        db.session.delete(credential)
        db.session.commit()
        
        return jsonify({'message': 'Credentials deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to delete credentials', 'error': str(e)}), 500

# Admin endpoints (simplified)
@app.route('/api/admin/applicants', methods=['GET', 'OPTIONS'])
def get_applicants():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        users = User.query.filter_by(role='applicant').all()
        return jsonify({
            'applicants': [{
                'id': user.id,
                'email': user.email,
                'name': f"{user.first_name} {user.last_name}",
                'curp': user.curp,
                'is_active': user.is_active,
                'is_approved': user.is_approved,
                'created_at': user.created_at.isoformat()
            } for user in users]
        })
    except Exception as e:
        return jsonify({'message': 'Failed to fetch applicants', 'error': str(e)}), 500

@app.route('/api/admin/tickets', methods=['GET', 'OPTIONS'])
def get_tickets():
    if request.method == 'OPTIONS':
        return '', 200
    
    # Return mock tickets for now
    return jsonify({
        'tickets': [
            {
                'id': '1',
                'title': 'Login Issue',
                'description': 'User cannot login',
                'status': 'open',
                'priority': 'high',
                'created_at': datetime.utcnow().isoformat()
            }
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)

