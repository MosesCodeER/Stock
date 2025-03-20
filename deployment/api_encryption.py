"""
API encryption middleware for Stock Tracker Application
"""

from flask import request, jsonify, g, current_app
from functools import wraps
import json
import base64
from encryption import encrypt_api_response, decrypt_api_response
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_encryption.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('api_encryption')

class APIEncryptionMiddleware:
    """Middleware for encrypting API responses"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        # Register after_request handler
        app.after_request(self.encrypt_response)
        
        # Register before_request handler
        app.before_request(self.decrypt_request)
        
        logger.info("API encryption middleware initialized")
    
    def encrypt_response(self, response):
        """Encrypt API response data"""
        # Only encrypt JSON responses from API endpoints
        if (response.content_type == 'application/json' and 
            request.path.startswith('/api/') and 
            response.status_code == 200):
            
            try:
                # Get original response data
                data = json.loads(response.get_data(as_text=True))
                
                # Encrypt sensitive fields
                encrypted_data = encrypt_api_response(data)
                
                # Replace response data
                response.set_data(json.dumps(encrypted_data))
                
                # Add header to indicate encryption
                response.headers['X-Encrypted-Response'] = 'true'
                
                logger.debug(f"Encrypted API response for {request.path}")
            except Exception as e:
                logger.error(f"Error encrypting API response: {str(e)}")
        
        return response
    
    def decrypt_request(self):
        """Decrypt encrypted request data"""
        # Only decrypt JSON requests to API endpoints
        if (request.content_type == 'application/json' and 
            request.path.startswith('/api/') and 
            request.method in ['POST', 'PUT', 'PATCH'] and
            request.headers.get('X-Encrypted-Request') == 'true'):
            
            try:
                # Get request data
                data = request.get_json(force=True)
                
                # Decrypt data
                decrypted_data = decrypt_api_response(data)
                
                # Store decrypted data for the view function
                g.decrypted_data = decrypted_data
                
                logger.debug(f"Decrypted API request for {request.path}")
            except Exception as e:
                logger.error(f"Error decrypting API request: {str(e)}")
    
def init_api_encryption(app):
    """Initialize API encryption middleware"""
    middleware = APIEncryptionMiddleware(app)
    return middleware

# Decorator for encrypting specific API responses
def encrypt_api(f):
    """Decorator to encrypt API responses"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Call the original function
        response = f(*args, **kwargs)
        
        # Only encrypt JSON responses
        if isinstance(response, dict):
            # Encrypt sensitive fields
            encrypted_data = encrypt_api_response(response)
            
            # Return jsonified response with encryption header
            resp = jsonify(encrypted_data)
            resp.headers['X-Encrypted-Response'] = 'true'
            return resp
        
        return response
    return decorated_function

# Decorator for decrypting API requests
def decrypt_api(f):
    """Decorator to decrypt API requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if request is encrypted
        if (request.content_type == 'application/json' and 
            request.method in ['POST', 'PUT', 'PATCH'] and
            request.headers.get('X-Encrypted-Request') == 'true'):
            
            try:
                # Get request data
                data = request.get_json(force=True)
                
                # Decrypt data
                decrypted_data = decrypt_api_response(data)
                
                # Store decrypted data for the view function
                g.decrypted_data = decrypted_data
            except Exception as e:
                logger.error(f"Error decrypting API request: {str(e)}")
        
        # Call the original function
        return f(*args, **kwargs)
    return decorated_function

# Function to get decrypted request data
def get_decrypted_data():
    """Get decrypted request data"""
    if hasattr(g, 'decrypted_data'):
        return g.decrypted_data
    
    # If not encrypted, return normal JSON data
    return request.get_json(silent=True)
