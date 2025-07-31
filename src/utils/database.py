"""
Database utilities for the loan platform
Handles initialization, migrations, and seeding with proper PostgreSQL transaction handling
"""

import os
from werkzeug.security import generate_password_hash
from src.models import db, User, BankProvider, Ticket, AuditLog

def migrate_schema():
    """
    ✅ FIXED: Handle database schema migration with proper transaction management
    This fixes the PostgreSQL transaction error
    """
    try:
        print("🔍 Checking database schema...")
        
        # ✅ CRITICAL FIX: Use separate connection for schema check
        with db.engine.connect() as conn:
            try:
                # Try to query the status column
                result = conn.execute(db.text("SELECT status FROM users LIMIT 1"))
                result.close()
                print("✅ Status column exists")
                return True
            except Exception as e:
                print(f"⚠️ Status column missing: {e}")
                
                try:
                    # ✅ FIXED: Use autocommit for DDL operations
                    conn.execute(db.text("COMMIT"))  # End any existing transaction
                    conn.execute(db.text("ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT 'pending'"))
                    conn.commit()
                    print("✅ Status column added successfully")
                    return True
                except Exception as migration_error:
                    print(f"❌ Failed to add status column: {migration_error}")
                    try:
                        conn.rollback()
                    except:
                        pass
                    return False
        
    except Exception as e:
        print(f"❌ Database migration failed: {e}")
        return False

def init_database():
    """Initialize database with tables and seed data - FIXED for PostgreSQL"""
    try:
        print("🚀 Initializing database...")
        
        # ✅ FIXED: Create tables first, then handle migration separately
        db.create_all()
        print("✅ Database tables created")
        
        # ✅ FIXED: Handle migration in separate transaction
        migrate_schema()
        
        # ✅ FIXED: Seed data with proper error handling
        try:
            seed_initial_data()
        except Exception as seed_error:
            print(f"⚠️ Seeding failed, but continuing: {seed_error}")
            # Don't fail the entire initialization if seeding fails
        
        print("✅ Database initialization completed")
        return True
        
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def seed_initial_data():
    """Seed database with initial data - FIXED for PostgreSQL"""
    try:
        # ✅ FIXED: Use raw SQL to check if data exists (avoids ORM transaction issues)
        with db.engine.connect() as conn:
            result = conn.execute(db.text("SELECT COUNT(*) FROM users"))
            user_count = result.scalar()
            
            if user_count > 0:
                print("✅ Database already contains data, skipping seed")
                return
        
        print("🌱 Seeding database with initial data...")
        
        # ✅ FIXED: Create users with explicit transaction management
        try:
            # Create admin user
            admin_user = User.create_user(
                email='admin@loanplatform.com',
                password='admin123',
                first_name='Admin',
                last_name='User',
                role='admin'
            )
            # ✅ FIXED: Set status safely
            try:
                admin_user.status = 'approved'
            except:
                pass  # Ignore if status column doesn't exist yet
            
            db.session.add(admin_user)
            
            # Create test applicant
            test_user = User.create_user(
                email='juan@socopwa.com',
                password='test123',
                first_name='Juan',
                last_name='Cordero',
                curp='CORJ850315HDFXXX01',
                phone='+52 55 1234 5678',
                role='applicant'
            )
            # ✅ FIXED: Set status safely
            try:
                test_user.status = 'pending'
            except:
                pass  # Ignore if status column doesn't exist yet
            
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
            
            # ✅ FIXED: Commit with proper error handling
            db.session.commit()
            print("✅ Database seeded successfully!")
            
        except Exception as e:
            print(f"❌ Database seeding failed: {e}")
            db.session.rollback()
            raise
        
    except Exception as e:
        print(f"❌ Database seeding failed: {e}")
        try:
            db.session.rollback()
        except:
            pass
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
    """Get database information with error handling"""
    try:
        # ✅ FIXED: Use raw SQL to avoid ORM transaction issues
        with db.engine.connect() as conn:
            user_result = conn.execute(db.text("SELECT COUNT(*) FROM users"))
            user_count = user_result.scalar()
            
            bank_result = conn.execute(db.text("SELECT COUNT(*) FROM bank_providers"))
            bank_count = bank_result.scalar()
            
            try:
                ticket_result = conn.execute(db.text("SELECT COUNT(*) FROM tickets"))
                ticket_count = ticket_result.scalar()
            except:
                ticket_count = 0
        
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

