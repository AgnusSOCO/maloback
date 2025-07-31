"""
Database models for the loan platform
"""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Import all models to ensure they're registered
from .user import User
from .bank import BankProvider, BankCredential
from .ticket import Ticket
from .audit import AuditLog

__all__ = ['db', 'User', 'BankProvider', 'BankCredential', 'Ticket', 'AuditLog']

