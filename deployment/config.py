"""
Production configuration for Stock Tracker Application
"""

import os

# Flask configuration
DEBUG = False
TESTING = False
SECRET_KEY = os.environ.get('SECRET_KEY', 'b9677417a293cb14b05863c40f5a7383db3c2645aad6129a')
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes

# Database configuration
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///production.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Security configuration
WTF_CSRF_ENABLED = True
WTF_CSRF_SECRET_KEY = os.environ.get('CSRF_SECRET_KEY', 'cdfb05dc4724c62315c2f27aa9c83f456343e9403c520353')

# Logging configuration
LOG_LEVEL = 'INFO'
LOG_DIR = 'logs'

# Monitoring configuration
MONITORING_ENABLED = True
AUDIT_DB_PATH = 'logs/audit.db'

# Rate limiting
RATELIMIT_DEFAULT = "100 per day, 10 per hour"
RATELIMIT_STORAGE_URL = "memory://"

# API configuration
API_RATE_LIMIT = 30  # requests per minute
