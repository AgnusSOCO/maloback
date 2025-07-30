#!/usr/bin/env python3
"""
Database seeding script for Mexican banks and initial data
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.models.user import db, BankProvider, User, UserRole
from werkzeug.security import generate_password_hash

def seed_mexican_banks():
    """Seed the database with major Mexican banks"""
    
    mexican_banks = [
        {
            'id': 'bbva',
            'display_name': 'BBVA México',
            'logo_url': '/assets/banks/bbva-logo.png'
        },
        {
            'id': 'santander',
            'display_name': 'Banco Santander México',
            'logo_url': '/assets/banks/santander-logo.png'
        },
        {
            'id': 'banamex',
            'display_name': 'Citibanamex',
            'logo_url': '/assets/banks/banamex-logo.png'
        },
        {
            'id': 'banorte',
            'display_name': 'Banorte',
            'logo_url': '/assets/banks/banorte-logo.png'
        },
        {
            'id': 'hsbc',
            'display_name': 'HSBC México',
            'logo_url': '/assets/banks/hsbc-logo.png'
        },
        {
            'id': 'scotiabank',
            'display_name': 'Scotiabank México',
            'logo_url': '/assets/banks/scotiabank-logo.png'
        },
        {
            'id': 'inbursa',
            'display_name': 'Banco Inbursa',
            'logo_url': '/assets/banks/inbursa-logo.png'
        },
        {
            'id': 'azteca',
            'display_name': 'Banco Azteca',
            'logo_url': '/assets/banks/azteca-logo.png'
        },
        {
            'id': 'bajio',
            'display_name': 'BanBajío',
            'logo_url': '/assets/banks/bajio-logo.png'
        },
        {
            'id': 'afirme',
            'display_name': 'Banca Afirme',
            'logo_url': '/assets/banks/afirme-logo.png'
        }
    ]
    
    for bank_data in mexican_banks:
        # Check if bank already exists
        existing_bank = BankProvider.query.filter_by(id=bank_data['id']).first()
        if not existing_bank:
            bank = BankProvider(**bank_data)
            db.session.add(bank)
            print(f"Added bank: {bank_data['display_name']}")
        else:
            print(f"Bank already exists: {bank_data['display_name']}")
    
    db.session.commit()
    print("Mexican banks seeded successfully!")

def create_admin_user():
    """Create a default admin user"""
    admin_email = "admin@loanplatform.com"
    admin_password = "admin123"  # Change this in production!
    
    # Check if admin already exists
    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        admin_user = User(
            email=admin_email,
            password_hash=generate_password_hash(admin_password),
            role=UserRole.ADMIN
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"Created admin user: {admin_email} / {admin_password}")
    else:
        print("Admin user already exists")

if __name__ == "__main__":
    from flask import Flask
    
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'database', 'app.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Seed data
        seed_mexican_banks()
        create_admin_user()
        
        print("Database seeding completed!")

