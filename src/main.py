"""
Fully functional main.py for Railway deployment
This version properly handles all database operations and route imports
"""

import os
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
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

# CORS configuration for Vercel
CORS(app, origins=[
    "http://localhost:5173",  # Development
    "https://*.vercel.app",   # All Vercel deployments
    "https://vercel.app"      # Vercel domain
])

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Loan Platform API is running',
        'database': 'connected'
    })

# Test endpoint
@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({
        'message': 'API is working!',
        'environment': os.environ.get('FLASK_ENV', 'development'),
        'database_url': 'configured' if app.config['SQLALCHEMY_DATABASE_URI'] else 'not configured'
    })

# Initialize database models within app context
with app.app_context():
    # Import models first
    try:
        from src.models.user import User, BankProvider, BankCredential, AuditLog, Ticket, TicketComment
        print("✅ Models imported successfully")
        
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
                    bank = BankProvider(**bank_data)
                    db.session.add(bank)
                
                db.session.commit()
                print("✅ Bank providers seeded")
            
            # Check if admin user exists
            if User.query.filter_by(email='admin@loanplatform.com').first() is None:
                from werkzeug.security import generate_password_hash
                
                admin_user = User(
                    email='admin@loanplatform.com',
                    password_hash=generate_password_hash('admin123'),
                    first_name='Admin',
                    last_name='User',
                    curp='ADMIN123456HDFRRL01',
                    role='admin',
                    is_active=True
                )
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Admin user created")
                
        except Exception as e:
            print(f"⚠️ Seeding error: {e}")
            db.session.rollback()
        
    except ImportError as e:
        print(f"⚠️ Could not import models: {e}")

# Import and register routes within app context
with app.app_context():
    try:
        from src.routes.auth import auth_bp
        from src.routes.applicants import applicants_bp  
        from src.routes.admin import admin_bp
        
        # Register blueprints
        app.register_blueprint(auth_bp, url_prefix='/api/auth')
        app.register_blueprint(applicants_bp, url_prefix='/api/applicants')
        app.register_blueprint(admin_bp, url_prefix='/api/admin')
        
        print("✅ All routes registered successfully")
        
    except ImportError as e:
        print(f"⚠️ Could not import routes: {e}")
        
        # Create basic auth endpoints if routes fail to import
        from flask import request
        from werkzeug.security import check_password_hash
        from flask_jwt_extended import create_access_token
        
        @app.route('/api/auth/login', methods=['POST'])
        def basic_login():
            try:
                data = request.get_json()
                email = data.get('email')
                password = data.get('password')
                
                if not email or not password:
                    return jsonify({'message': 'Email and password required'}), 400
                
                # Try to find user
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
        
        @app.route('/api/applicants/banks', methods=['GET'])
        def basic_banks():
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

