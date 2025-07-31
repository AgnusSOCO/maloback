"""
Audit log model for tracking system actions
"""

import uuid
from datetime import datetime

# Import shared db instance
from . import db

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(36), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='audit_logs')
    
    def to_dict(self):
        """Convert to dictionary"""
        try:
            user_name = self.user.name if self.user else 'Unknown'
        except:
            user_name = 'Unknown'
        
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user_name': user_name,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def log_action(cls, user_id, action, resource_type, resource_id=None, details=None, ip_address=None, user_agent=None):
        """Log an action"""
        log = cls(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        return log
    
    @classmethod
    def get_by_user(cls, user_id, limit=100):
        """Get audit logs by user"""
        return cls.query.filter_by(user_id=user_id).order_by(cls.created_at.desc()).limit(limit).all()
    
    @classmethod
    def get_recent(cls, limit=100):
        """Get recent audit logs"""
        return cls.query.order_by(cls.created_at.desc()).limit(limit).all()
    
    def __repr__(self):
        return f'<AuditLog {self.action} on {self.resource_type}>'

