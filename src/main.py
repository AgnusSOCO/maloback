"""
Main application file for the modular loan platform
✅ Fixes HTTP 500 login error with database migration
✅ Preserves all functionality: admin password visibility, status system, tickets
✅ Proper modular structure
✅ FIXED: JSON serialization error in health check
"""

import os
import sys
from datetime import datetime
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS

# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Import models and utilities
from src.models import db
from src.utils.database import init_database, get_database_info

# Import route blueprints
from src.routes.auth import auth_bp
from src.routes.banks import banks_bp
from src.routes.admin import admin_bp
from src.routes.tickets import tickets_bp

def create_app():
    """Application factory"""
    app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # ✅ RAILWAY COMPATIBILITY: Use PostgreSQL URL from Railway or fallback to SQLite
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        # Railway PostgreSQL
        app.config['SQLALCHEMY_DATABASE_URI'] = database_url
        print("✅ Using Railway PostgreSQL database")
    else:
        # Local SQLite
        app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'database', 'app.db')}"
        print("✅ Using local SQLite database")
    
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # ✅ CORS CONFIGURATION for Vercel and Railway
    CORS(app, origins=[
        'https://malofront.vercel.app',
        'https://*.vercel.app',
        'http://localhost:5173',
        'http://localhost:3000',
        'http://localhost:5000'
    ])
    
    # Initialize database
    db.init_app(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(banks_bp, url_prefix='/api/applicants')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(tickets_bp, url_prefix='/api/tickets')
    
    # Health check and basic routes
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """
        Health check endpoint
        ✅ FIXED: JSON serialization error
        """
        try:
            db_info = get_database_info()
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.utcnow().isoformat(),  # ✅ FIXED: Use serializable timestamp
                'cors': 'enabled',
                'database': db_info['status'],
                'features': ['auth', 'bank_credentials', 'tickets', 'admin_panel'],
                'version': '2.0.0-modular'
            }), 200
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()  # ✅ FIXED: Use serializable timestamp
            }), 500
    
    @app.route('/api/test', methods=['GET'])
    def test():
        """Test endpoint"""
        return jsonify({
            'message': 'Modular API is working!',
            'environment': os.environ.get('FLASK_ENV', 'production'),
            'features': ['auth', 'bank_credentials', 'tickets', 'admin_panel'],
            'version': '2.0.0-modular',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    
    # Frontend serving routes
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve(path):
        """Serve frontend files"""
        static_folder_path = app.static_folder
        if static_folder_path is None:
            return "Static folder not configured", 404

        if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
            return send_from_directory(static_folder_path, path)
        else:
            index_path = os.path.join(static_folder_path, 'index.html')
            if os.path.exists(index_path):
                return send_from_directory(static_folder_path, 'index.html')
            else:
                return jsonify({
                    'message': 'Loan Platform API',
                    'version': '2.0.0-modular',
                    'status': 'running',
                    'timestamp': datetime.utcnow().isoformat()
                }), 200
    
    # ✅ CRITICAL: Initialize database with migration on startup
    with app.app_context():
        try:
            print("🚀 Initializing modular loan platform...")
            success = init_database()
            if success:
                print("✅ Database initialization completed successfully")
            else:
                print("⚠️ Database initialization had issues")
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            import traceback
            traceback.print_exc()
    
    return app

# Create the app instance
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    print(f"🚀 Starting modular loan platform on port {port}")
    print(f"🔧 Debug mode: {debug}")
    print(f"🌐 CORS enabled for multiple origins")
    print(f"✅ All features available: auth, admin, tickets, bank credentials")
    
    app.run(host='0.0.0.0', port=port, debug=debug)

