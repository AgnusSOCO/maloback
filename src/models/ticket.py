"""
Ticket model for the loan platform support system
"""

import uuid
from datetime import datetime

# Import shared db instance
from . import db

class Ticket(db.Model):
    __tablename__ = 'tickets'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='open')  # open, in_progress, resolved, closed
    priority = db.Column(db.String(20), default='medium')  # low, medium, high, urgent
    category = db.Column(db.String(50), default='general')  # general, technical, billing, support
    
    # User information
    created_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    assigned_to = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_tickets')
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')
    
    def to_dict(self):
        """Convert to dictionary"""
        try:
            creator_name = self.creator.name if self.creator else 'Unknown'
        except:
            creator_name = 'Unknown'
            
        try:
            assignee_name = self.assignee.name if self.assignee else None
        except:
            assignee_name = None
        
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'priority': self.priority,
            'category': self.category,
            'created_by': self.created_by,
            'creator_name': creator_name,
            'assigned_to': self.assigned_to,
            'assignee_name': assignee_name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }
    
    @classmethod
    def get_all(cls):
        """Get all tickets"""
        return cls.query.all()
    
    @classmethod
    def get_by_user(cls, user_id):
        """Get tickets created by user"""
        return cls.query.filter_by(created_by=user_id).all()
    
    @classmethod
    def get_by_status(cls, status):
        """Get tickets by status"""
        return cls.query.filter_by(status=status).all()
    
    @classmethod
    def create_ticket(cls, title, description, created_by, **kwargs):
        """Create new ticket"""
        ticket = cls(
            title=title,
            description=description,
            created_by=created_by,
            **kwargs
        )
        return ticket
    
    def update_status(self, new_status):
        """Update ticket status"""
        self.status = new_status
        self.updated_at = datetime.utcnow()
        
        if new_status == 'resolved':
            self.resolved_at = datetime.utcnow()
    
    def assign_to(self, user_id):
        """Assign ticket to user"""
        self.assigned_to = user_id
        self.updated_at = datetime.utcnow()
    
    def __repr__(self):
        return f'<Ticket {self.title[:50]}>'

