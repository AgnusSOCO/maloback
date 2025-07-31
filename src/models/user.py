"""
User model with backward compatibility for database schema
Handles missing 'status' column gracefully
"""

import uuid
from datetime import datetime
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash

# Import shared db instance
from . import db

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
    is_active = db.Column(db.Boolean, default=True)
    
    # ✅ BACKWARD COMPATIBLE: Status column with migration handling
    # This will be added via migration if missing
    status = db.Column(db.String(20), default='pending')
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        # Set default status if not provided
        if not hasattr(self, 'status') or self.status is None:
            self.status = 'pending'
    
    @property
    def name(self):
        """Get user's display name with error handling"""
        try:
            if self.first_name and self.last_name:
                return f"{self.first_name} {self.last_name}"
            return self.email.split('@')[0] if self.email else 'Unknown User'
        except Exception:
            return 'Unknown User'
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self, include_sensitive=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'name': self.name,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'curp': self.curp,
            'phone': self.phone,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        
        # ✅ BACKWARD COMPATIBLE: Handle missing status column
        try:
            data['status'] = getattr(self, 'status', 'pending')
        except Exception:
            data['status'] = 'pending'
        
        if include_sensitive:
            data['password_hash'] = self.password_hash
        
        return data
    
    @classmethod
    def get_by_email(cls, email):
        """Get user by email with error handling"""
        try:
            return cls.query.filter_by(email=email).first()
        except Exception as e:
            print(f"Error getting user by email: {e}")
            return None
    
    @classmethod
    def create_user(cls, email, password, **kwargs):
        """Create new user"""
        user = cls(
            email=email,
            **kwargs
        )
        user.set_password(password)
        return user
    
    @staticmethod
    def check_and_migrate_schema():
        """
        Check if status column exists and add it if missing
        This handles the database migration issue
        """
        try:
            # Try to query the status column
            db.session.execute(text("SELECT status FROM users LIMIT 1"))
            print("✅ Status column exists")
            return True
        except Exception as e:
            print(f"⚠️ Status column missing: {e}")
            try:
                # Add the status column
                db.session.execute(text("ALTER TABLE users ADD COLUMN status VARCHAR(20) DEFAULT 'pending'"))
                db.session.commit()
                print("✅ Status column added successfully")
                return True
            except Exception as migration_error:
                print(f"❌ Failed to add status column: {migration_error}")
                return False
    
    def __repr__(self):
        return f'<User {self.email}>'

