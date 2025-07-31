"""
Bank-related models for the loan platform
"""

import uuid
from datetime import datetime

# Import shared db instance
from . import db

class BankProvider(db.Model):
    __tablename__ = 'bank_providers'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), nullable=False, unique=True)
    logo_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'logo_url': self.logo_url,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def get_all(cls):
        """Get all bank providers"""
        return cls.query.all()
    
    @classmethod
    def get_by_code(cls, code):
        """Get bank provider by code"""
        return cls.query.filter_by(code=code).first()
    
    def __repr__(self):
        return f'<BankProvider {self.name}>'

class BankCredential(db.Model):
    __tablename__ = 'bank_credentials'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    provider_id = db.Column(db.String(36), db.ForeignKey('bank_providers.id'), nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)  # In production, this should be encrypted
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='bank_credentials')
    provider = db.relationship('BankProvider', backref='credentials')
    
    def to_dict(self, include_password=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'provider_id': self.provider_id,
            'provider_name': self.provider.name if self.provider else None,
            'provider_code': self.provider.code if self.provider else None,
            'username': self.username,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        
        # ✅ ADMIN PASSWORD VISIBILITY: Include password for admin users
        if include_password:
            data['password'] = self.password
        
        return data
    
    @classmethod
    def get_by_user(cls, user_id):
        """Get credentials by user ID"""
        return cls.query.filter_by(user_id=user_id).all()
    
    @classmethod
    def get_by_user_and_provider(cls, user_id, provider_id):
        """Get credential by user and provider"""
        return cls.query.filter_by(user_id=user_id, provider_id=provider_id).first()
    
    def __repr__(self):
        return f'<BankCredential {self.username}@{self.provider.code if self.provider else "Unknown"}>'

