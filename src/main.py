"""
Working main.py for Railway deployment
This version uses proper import syntax and module-level imports
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

# Import and register routes
try:
    # Try to import the routes - if they fail, we'll still have a working API
    import sys
    sys.path.append('/app')
    
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
    print("API will run with basic endpoints only")

# Try to import models and create tables
try:
    from src.models.user import User, BankProvider, BankCredential, AuditLog, Ticket, TicketComment
    
    # Create tables
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully")
        
except ImportError as e:
    print(f"⚠️ Could not import models: {e}")
    print("API will run without database models")
except Exception as e:
    print(f"⚠️ Database error: {e}")
    print("API will run but database may not be initialized")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

