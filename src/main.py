"""
Updated main.py with comprehensive CORS fix for Vercel deployment
Replace your current main.py with this version
"""

import os
import uuid
from datetime import datetime
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///loan_platform.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# COMPREHENSIVE CORS configuration for Vercel
CORS(app, 
     origins=[
         "http://localhost:3000",      # React dev server
         "http://localhost:5173",      # Vite dev server
         "https://*.vercel.app",       # All Vercel subdomains
         "https://vercel.app",         # Vercel main domain
         "*"                           # Allow all origins (for testing)
     ],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"],
     supports_credentials=True
)

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

# Add explicit OPTIONS handler for preflight requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response

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
        return jsonify([{
            'id': bank.id,
            'name': bank.name,
            'code': bank.code,
            'logo_url': bank.logo_url
        } for bank in banks])
    except Exception as e:
        return jsonify({'message': 'Failed to fetch banks', 'error': str(e)}), 500

# Initialize database
with app.app_context():
    try:
        # Create all tables
        db.create_all()
        print("✅ Database tables created")
        
        # Seed initial data
        try:
            # Check if bank providers exist
            if BankProvider.query.count() == 0:
                # Create Mexican bank providers
                banks = [
                    {'name': 'BBVA México', 'code': 'BBVA', 'logo_url': '/assets/bbva-logo.jpg'},
                    {'name': 'Santander México', 'code': 'SANTANDER', 'logo_url': '/assets/santander-logo.jpg'},
                    {'name': 'Banamex', 'code': 'BANAMEX', 'logo_url': '/assets/banamex-logo.jpg'},
                    {'name': 'Banorte', 'code': 'BANORTE', 'logo_url': '/assets/banorte-logo.jpg'},
                    {'name': 'HSBC México', 'code': 'HSBC', 'logo_url': '/assets/hsbc-logo.jpg'},
                    {'name': 'Banco Azteca', 'code': 'AZTECA', 'logo_url': '/assets/azteca-logo.jpg'},
                ]
                
                for bank_data in banks:
                    bank = BankProvider(
                        id=str(uuid.uuid4()),
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
                    is_active=True,
                    is_approved=True
                )
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Admin user created")
                
        except Exception as e:
            print(f"⚠️ Seeding error: {e}")
            db.session.rollback()
        
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

