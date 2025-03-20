"""
Security utilities for Stock Tracker Application
"""

import secrets
import string
import re
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import request, session, abort
from functools import wraps
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('security')

# Security constants
CSRF_TOKEN_LENGTH = 32
SESSION_ID_LENGTH = 64
PASSWORD_RESET_TOKEN_LENGTH = 64
API_KEY_LENGTH = 32
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 15  # minutes

# Encryption key (in production, this would be stored securely, not in code)
# Generate a key and save it
def generate_key():
    """Generate a key for encryption and save it to a file"""
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)
    return key

def load_key():
    """Load the encryption key"""
    if not os.path.exists('secret.key'):
        return generate_key()
    with open('secret.key', 'rb') as key_file:
        return key_file.read()

# Initialize encryption
encryption_key = load_key()
cipher_suite = Fernet(encryption_key)

def encrypt_data(data):
    """Encrypt sensitive data"""
    if isinstance(data, str):
        data = data.encode()
    encrypted_data = cipher_suite.encrypt(data)
    return encrypted_data

def decrypt_data(encrypted_data):
    """Decrypt encrypted data"""
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data.decode()

def generate_csrf_token():
    """Generate a secure CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(CSRF_TOKEN_LENGTH)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    if not token or token != session.get('csrf_token'):
        logger.warning(f'CSRF validation failed: {request.remote_addr}')
        return False
    return True

def csrf_protect(f):
    """Decorator to protect against CSRF attacks"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not validate_csrf_token(token):
                logger.warning(f'CSRF attack detected from IP: {request.remote_addr}')
                abort(403)
        return f(*args, **kwargs)
    return decorated_function

def generate_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()_-+=<>?'
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        # Check if password meets complexity requirements
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in '!@#$%^&*()_-+=<>?' for c in password)):
            return password

def validate_password_strength(password):
    """Validate password meets security requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*()_\-+={}[\]|:;"\'<>,.?/~`]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password meets requirements"

def hash_password(password, salt=None):
    """Hash a password with a salt using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    password_hash = kdf.derive(password.encode())
    
    # Return both the salt and the hash
    return salt, password_hash

def verify_password(password, salt, stored_hash):
    """Verify a password against a stored hash"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    try:
        kdf.verify(password.encode(), stored_hash)
        return True
    except:
        return False

def generate_reset_token():
    """Generate a secure token for password reset"""
    return secrets.token_urlsafe(PASSWORD_RESET_TOKEN_LENGTH)

def hash_reset_token(token):
    """Hash a reset token for secure storage"""
    return hashlib.sha256(token.encode()).hexdigest()

def sanitize_input(input_string):
    """Sanitize user input to prevent XSS attacks"""
    # Replace potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', input_string)
    return sanitized

def validate_email(email):
    """Validate email format"""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def validate_username(username):
    """Validate username format"""
    # Allow letters, numbers, underscores, hyphens, 3-50 characters
    username_regex = r'^[a-zA-Z0-9_-]{3,50}$'
    return re.match(username_regex, username) is not None

def generate_api_key():
    """Generate a secure API key"""
    return secrets.token_urlsafe(API_KEY_LENGTH)

def log_security_event(event_type, user_id=None, details=None, ip=None):
    """Log security events"""
    if ip is None:
        ip = request.remote_addr
    
    log_data = {
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip,
        'user_agent': request.user_agent.string if request else 'N/A',
        'details': details
    }
    
    logger.info(f"Security Event: {event_type} - User: {user_id} - IP: {ip} - Details: {details}")
    return log_data

def is_rate_limited(key, limit=5, period=60):
    """
    Check if a request should be rate limited
    
    Args:
        key: Unique identifier for the request (e.g., IP address, user ID)
        limit: Maximum number of requests allowed in the period
        period: Time period in seconds
        
    Returns:
        bool: True if request should be rate limited, False otherwise
    """
    # In a real application, this would use Redis or a similar cache
    # For this demo, we'll use a simple in-memory dictionary
    from datetime import datetime, timedelta
    
    # Initialize rate limiting storage if it doesn't exist
    if not hasattr(is_rate_limited, 'storage'):
        is_rate_limited.storage = {}
    
    current_time = datetime.utcnow()
    
    # Clean up old entries
    for k in list(is_rate_limited.storage.keys()):
        if is_rate_limited.storage[k]['reset_time'] < current_time:
            del is_rate_limited.storage[k]
    
    # Check if key exists
    if key not in is_rate_limited.storage:
        is_rate_limited.storage[key] = {
            'count': 1,
            'reset_time': current_time + timedelta(seconds=period)
        }
        return False
    
    # Check if limit exceeded
    if is_rate_limited.storage[key]['count'] >= limit:
        return True
    
    # Increment count
    is_rate_limited.storage[key]['count'] += 1
    return False
