"""
Database utilities for the loan platform
Handles initialization, migrations, and seeding
"""

import os
from werkzeug.security import generate_password_hash
from src.models import db, User, BankProvider, Ticket, AuditLog

def migrate_schema():
    """
    ✅ CRITICAL: Handle database schema migration
    This fixes the HTTP 500 login error by adding missing columns
    """
    try:
        print("🔍 Checking database schema...")
        
        # Check and migrate User model (add status column if missing)
        success = User.check_and_migrate_schema()
        
        if success:
            print("✅ Database schema migration completed successfully")
        else:
            print("⚠️ Database schema migration had issues")
        
        return success
        
    except Exception as e:
        print(f"❌ Database migration failed: {e}")
        return False

def init_database():
    """Initialize database with tables and seed data"""
    try:
        print("🚀 Initializing database...")
        
        # Create all tables
        db.create_all()
        print("✅ Database tables created")
        
        # Handle schema migration (add missing columns)
        migrate_schema()
        
        # Seed initial data if needed
        seed_initial_data()
        
        print("✅ Database initialization completed")
        return True
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def seed_initial_data():
    """Seed database with initial data"""
    try:
        # Check if we need to seed data
        if User.query.count() > 0:
            print("✅ Database already contains data, skipping seed")
            return
        
        print("🌱 Seeding database with initial data...")
        
        # Create admin user
        admin_user = User.create_user(
            email='admin@loanplatform.com',
            password='admin123',
            first_name='Admin',
            last_name='User',
            role='admin',
            status='approved'
        )
        db.session.add(admin_user)
        
        # Create test applicant
        test_user = User.create_user(
            email='juan@socopwa.com',
            password='test123',
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
        
        # Commit all changes
        db.session.commit()
        print("✅ Database seeded successfully!")
        
    except Exception as e:
        print(f"❌ Database seeding failed: {e}")
        db.session.rollback()
        raise

def reset_database():
    """Reset database (for development only)"""
    try:
        print("⚠️ Resetting database...")
        db.drop_all()
        db.create_all()
        migrate_schema()
        seed_initial_data()
        print("✅ Database reset completed")
        
    except Exception as e:
        print(f"❌ Database reset failed: {e}")
        raise

def get_database_info():
    """Get database information"""
    try:
        user_count = User.query.count()
        bank_count = BankProvider.query.count()
        ticket_count = Ticket.query.count()
        
        return {
            'users': user_count,
            'banks': bank_count,
            'tickets': ticket_count,
            'status': 'connected'
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

