from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import enum

db = SQLAlchemy()

class UserRole(enum.Enum):
    APPLICANT = 'applicant'
    PROMOTER = 'promoter'
    ADMIN = 'admin'

class TicketStatus(enum.Enum):
    OPEN = 'open'
    IN_PROGRESS = 'in_progress'
    CLOSED = 'closed'

class TicketPriority(enum.Enum):
    LOW = 'low'
    NORMAL = 'normal'
    HIGH = 'high'

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    promoter = db.relationship('Promoter', backref='user', uselist=False)
    applicant = db.relationship('Applicant', backref='user', uselist=False)

    def __repr__(self):
        return f'<User {self.email}>'

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role.value,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Promoter(db.Model):
    __tablename__ = 'promoters'
    
    id = db.Column(db.String(36), db.ForeignKey('users.id'), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    phone = db.Column(db.String(20))
    
    # Relationships
    applicants = db.relationship('Applicant', backref='promoter')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'phone': self.phone
        }

class Applicant(db.Model):
    __tablename__ = 'applicants'
    
    id = db.Column(db.String(36), db.ForeignKey('users.id'), primary_key=True)
    promoter_id = db.Column(db.String(36), db.ForeignKey('promoters.id'))
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    curp = db.Column(db.String(18))  # Mexican CURP
    address_json = db.Column(db.Text)  # JSON string for address
    contract_signed = db.Column(db.Boolean, default=False)
    contract_scan_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    bank_credentials = db.relationship('BankCredential', backref='applicant')
    tickets = db.relationship('Ticket', backref='applicant')

    def to_dict(self):
        return {
            'id': self.id,
            'promoter_id': self.promoter_id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'phone': self.phone,
            'curp': self.curp,
            'address_json': self.address_json,
            'contract_signed': self.contract_signed,
            'contract_scan_url': self.contract_scan_url,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class BankProvider(db.Model):
    __tablename__ = 'bank_providers'
    
    id = db.Column(db.String(50), primary_key=True)  # e.g., 'bbva', 'santander'
    display_name = db.Column(db.String(100), nullable=False)
    logo_url = db.Column(db.String(500))
    
    # Relationships
    credentials = db.relationship('BankCredential', backref='provider')

    def to_dict(self):
        return {
            'id': self.id,
            'display_name': self.display_name,
            'logo_url': self.logo_url
        }

class BankCredential(db.Model):
    __tablename__ = 'bank_credentials'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    applicant_id = db.Column(db.String(36), db.ForeignKey('applicants.id'), nullable=False)
    provider_id = db.Column(db.String(50), db.ForeignKey('bank_providers.id'), nullable=False)
    username_enc = db.Column(db.LargeBinary)  # Encrypted username
    password_enc = db.Column(db.LargeBinary)  # Encrypted password
    iv = db.Column(db.LargeBinary)  # Initialization vector for encryption
    kek_version = db.Column(db.Integer, default=1)  # Key encryption key version
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self, include_credentials=False):
        result = {
            'id': self.id,
            'applicant_id': self.applicant_id,
            'provider_id': self.provider_id,
            'kek_version': self.kek_version,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
        if include_credentials:
            # Note: In production, this would decrypt the credentials
            result['username'] = '[ENCRYPTED]'
            result['password'] = '[ENCRYPTED]'
        return result

class Ticket(db.Model):
    __tablename__ = 'tickets'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    applicant_id = db.Column(db.String(36), db.ForeignKey('applicants.id'), nullable=False)
    created_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    assigned_to = db.Column(db.String(36), db.ForeignKey('users.id'))
    status = db.Column(db.Enum(TicketStatus), default=TicketStatus.OPEN)
    priority = db.Column(db.Enum(TicketPriority), default=TicketPriority.NORMAL)
    title = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    comments = db.relationship('TicketComment', backref='ticket')
    creator = db.relationship('User', foreign_keys=[created_by])
    assignee = db.relationship('User', foreign_keys=[assigned_to])

    def to_dict(self):
        return {
            'id': self.id,
            'applicant_id': self.applicant_id,
            'created_by': self.created_by,
            'assigned_to': self.assigned_to,
            'status': self.status.value,
            'priority': self.priority.value,
            'title': self.title,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class TicketComment(db.Model):
    __tablename__ = 'ticket_comments'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ticket_id = db.Column(db.String(36), db.ForeignKey('tickets.id'), nullable=False)
    author_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    author = db.relationship('User', backref='ticket_comments')

    def to_dict(self):
        return {
            'id': self.id,
            'ticket_id': self.ticket_id,
            'author_id': self.author_id,
            'body': self.body,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    subject_id = db.Column(db.String(36))  # ID of the subject being acted upon
    audit_metadata = db.Column(db.Text)  # JSON string for additional data
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    actor = db.relationship('User', backref='audit_logs')

    def to_dict(self):
        return {
            'id': self.id,
            'actor_id': self.actor_id,
            'action': self.action,
            'subject_id': self.subject_id,
            'metadata': self.audit_metadata,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
