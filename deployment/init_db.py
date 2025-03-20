"""
Initialize the database for Stock Tracker Application
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime

# Create Flask app
app = Flask(__name__)
app.config.from_pyfile('config.py')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    def __repr__(self):
        return f"User('{self.email}', '{self.role}')"

def init_db():
    """Initialize the database and create admin user"""
    # Create database tables
    db.create_all()
    
    # Check if admin user exists
    admin = User.query.filter_by(email='admin@example.com').first()
    if not admin:
        # Create admin user with password 'persona101!'
        hashed_password = bcrypt.generate_password_hash('persona101!').decode('utf-8')
        admin = User(email='admin@example.com', password_hash=hashed_password, role='admin')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully.")
    else:
        print("Admin user already exists.")

if __name__ == '__main__':
    init_db()
