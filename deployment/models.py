"""
Models for Stock Tracker Application
Includes User model for authentication and security
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime
import os

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model, UserMixin):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    login_attempts = db.Column(db.Integer, default=0)
    
    # Relationships
    watchlists = db.relationship('Watchlist', backref='owner', lazy=True)
    login_logs = db.relationship('LoginLog', backref='user', lazy=True)
    
    def set_password(self, password):
        """Hash password before storing"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        """Check if password matches hash"""
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update last login time"""
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def increment_login_attempts(self):
        """Increment failed login attempts"""
        self.login_attempts += 1
        db.session.commit()
    
    def reset_login_attempts(self):
        """Reset login attempts counter"""
        self.login_attempts = 0
        db.session.commit()
    
    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin'
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"

class Watchlist(db.Model):
    """Watchlist model for storing user's watchlists"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    stocks = db.relationship('WatchlistStock', backref='watchlist', lazy=True, cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"Watchlist('{self.name}', user_id={self.user_id})"

class WatchlistStock(db.Model):
    """Model for stocks in a watchlist"""
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(10), nullable=False)
    watchlist_id = db.Column(db.Integer, db.ForeignKey('watchlist.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"WatchlistStock('{self.symbol}', watchlist_id={self.watchlist_id})"

class LoginLog(db.Model):
    """Model for tracking login attempts"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(255))
    success = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f"LoginLog(user_id={self.user_id}, success={self.success})"

class AuditLog(db.Model):
    """Model for tracking user actions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable for system actions
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))  # e.g., 'watchlist', 'stock', 'user'
    resource_id = db.Column(db.String(50))    # ID of the resource being acted upon
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    details = db.Column(db.Text)
    
    def __repr__(self):
        return f"AuditLog(user_id={self.user_id}, action='{self.action}', resource='{self.resource_type}')"

def init_db(app):
    """Initialize the database and create tables"""
    db.init_app(app)
    bcrypt.init_app(app)
    
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@stocktracker.com',
                role='admin',
                is_active=True
            )
            admin.set_password('persona101!')  # Set the specified password
            db.session.add(admin)
            db.session.commit()
            
            # Create default watchlist for admin
            default_watchlist = Watchlist(name='Default', user_id=admin.id)
            db.session.add(default_watchlist)
            db.session.commit()
            
            # Add default stocks to watchlist
            default_stocks = ['AAPL', 'MSFT', 'GOOGL', 'AMZN', 'META']
            for symbol in default_stocks:
                stock = WatchlistStock(symbol=symbol, watchlist_id=default_watchlist.id)
                db.session.add(stock)
            
            db.session.commit()
