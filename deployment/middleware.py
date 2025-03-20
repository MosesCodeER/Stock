"""
Security middleware for Stock Tracker Application
"""

from flask import request, abort, session, current_app
import time
import re
import logging
import json
from functools import wraps
from security import log_security_event, is_rate_limited

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('middleware.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('middleware')

class SecurityMiddleware:
    """Middleware for handling security concerns"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Register error handlers
        app.register_error_handler(400, self.bad_request_handler)
        app.register_error_handler(401, self.unauthorized_handler)
        app.register_error_handler(403, self.forbidden_handler)
        app.register_error_handler(404, self.not_found_handler)
        app.register_error_handler(429, self.too_many_requests_handler)
        app.register_error_handler(500, self.server_error_handler)
    
    def before_request(self):
        """Process request before it reaches the view"""
        # Skip for static files
        if request.path.startswith('/static'):
            return
        
        # Store request start time for performance monitoring
        request.start_time = time.time()
        
        # Rate limiting
        if self._should_rate_limit():
            if is_rate_limited(f"{request.remote_addr}:{request.endpoint}", limit=30, period=60):
                log_security_event('rate_limit_exceeded', 
                                  details=f"Rate limit exceeded for IP: {request.remote_addr}, Endpoint: {request.endpoint}")
                abort(429)
        
        # Check for suspicious input
        if self._has_suspicious_input():
            log_security_event('suspicious_input', 
                              details=f"Suspicious input detected from IP: {request.remote_addr}")
            abort(400)
        
        # Check for SQL injection attempts
        if self._has_sql_injection():
            log_security_event('sql_injection_attempt', 
                              details=f"SQL injection attempt detected from IP: {request.remote_addr}")
            abort(403)
        
        # Check for XSS attempts
        if self._has_xss_attempt():
            log_security_event('xss_attempt', 
                              details=f"XSS attempt detected from IP: {request.remote_addr}")
            abort(403)
    
    def after_request(self, response):
        """Process response before it's sent to the client"""
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        
        # Log response time for performance monitoring
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time
            logger.info(f"Request to {request.path} took {duration:.4f}s")
        
        return response
    
    def _should_rate_limit(self):
        """Determine if request should be rate limited"""
        # Don't rate limit static files
        if request.path.startswith('/static'):
            return False
        
        # Apply stricter rate limiting to authentication endpoints
        if request.endpoint and request.endpoint.startswith('auth.'):
            return True
        
        # Apply rate limiting to API endpoints
        if request.path.startswith('/api/'):
            return True
        
        return False
    
    def _has_suspicious_input(self):
        """Check for suspicious input patterns"""
        # Check URL for suspicious patterns
        suspicious_patterns = [
            r'\.\./',                # Directory traversal
            r'%2e%2e%2f',            # URL encoded directory traversal
            r'etc/passwd',           # Common file access attempt
            r'cmd=',                 # Command injection
            r'exec\(',               # PHP code injection
            r'system\(',             # System command execution
            r'document\.cookie',     # Cookie stealing
            r'<script',              # Script tag
            r'javascript:',          # JavaScript protocol
            r'onerror=',             # Event handler injection
            r'data:text/html',       # Data URI scheme
            r'base64',               # Base64 encoding (often used to obfuscate)
            r'eval\(',               # JavaScript eval
            r'fromCharCode',         # Character code conversion
            r'encodeURIComponent',   # URL encoding
        ]
        
        # Check URL
        url = request.url.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, url):
                return True
        
        # Check query parameters
        for key, value in request.args.items():
            if isinstance(value, str):
                for pattern in suspicious_patterns:
                    if re.search(pattern, value.lower()):
                        return True
        
        # Check form data
        if request.form:
            for key, value in request.form.items():
                if isinstance(value, str):
                    for pattern in suspicious_patterns:
                        if re.search(pattern, value.lower()):
                            return True
        
        # Check JSON data
        if request.is_json:
            try:
                json_data = request.get_json()
                if json_data:
                    json_str = json.dumps(json_data)
                    for pattern in suspicious_patterns:
                        if re.search(pattern, json_str.lower()):
                            return True
            except:
                # If JSON parsing fails, it might be malformed or an attack
                return True
        
        return False
    
    def _has_sql_injection(self):
        """Check for SQL injection attempts"""
        sql_patterns = [
            r'(\%27)|(\')|(\-\-)|(\%23)|(#)',  # Single quotes, comments
            r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))',  # SQL meta-characters
            r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))',  # 'or' expressions
            r'((\%27)|(\'))union',  # UNION keyword
            r'exec(\s|\+)+(s|x)p\w+',  # Stored procedures
            r'insert(\s|\+)+into(\s|\+)+\w+',  # INSERT INTO
            r'select(\s|\+)+\w+(\s|\+)+from',  # SELECT FROM
            r'drop(\s|\+)+table',  # DROP TABLE
            r'alter(\s|\+)+table',  # ALTER TABLE
            r'delete(\s|\+)+from',  # DELETE FROM
            r'update(\s|\+)+\w+(\s|\+)+set',  # UPDATE SET
        ]
        
        # Check all request parameters
        for key, value in request.values.items():
            if isinstance(value, str):
                for pattern in sql_patterns:
                    if re.search(pattern, value.lower()):
                        return True
        
        # Check JSON data
        if request.is_json:
            try:
                json_data = request.get_json()
                if json_data:
                    json_str = json.dumps(json_data)
                    for pattern in sql_patterns:
                        if re.search(pattern, json_str.lower()):
                            return True
            except:
                pass
        
        return False
    
    def _has_xss_attempt(self):
        """Check for XSS attempts"""
        xss_patterns = [
            r'<[^>]*script',  # Script tags
            r'javascript:',   # JavaScript protocol
            r'expression\(',  # CSS expressions
            r'vbscript:',     # VBScript protocol
            r'onload=',       # Event handlers
            r'onclick=',
            r'onmouseover=',
            r'onerror=',
            r'onmouseout=',
            r'onfocus=',
            r'onblur=',
            r'onkeyup=',
            r'onkeydown=',
            r'onkeypress=',
            r'onchange=',
            r'onsubmit=',
            r'document\.cookie',  # Cookie access
            r'document\.location',  # Location manipulation
            r'document\.referrer',  # Referrer access
            r'window\.location',  # Window location
            r'eval\(',         # JavaScript eval
            r'setTimeout\(',   # JavaScript timing functions
            r'setInterval\(',
            r'new\s+Function\(',  # Function constructor
            r'document\.write\(',  # Document write
            r'\.innerHTML',    # innerHTML manipulation
            r'\.outerHTML',    # outerHTML manipulation
            r'\.insertAdjacentHTML',  # insertAdjacentHTML
        ]
        
        # Check all request parameters
        for key, value in request.values.items():
            if isinstance(value, str):
                for pattern in xss_patterns:
                    if re.search(pattern, value.lower()):
                        return True
        
        # Check JSON data
        if request.is_json:
            try:
                json_data = request.get_json()
                if json_data:
                    json_str = json.dumps(json_data)
                    for pattern in xss_patterns:
                        if re.search(pattern, json_str.lower()):
                            return True
            except:
                pass
        
        return False
    
    # Error handlers
    def bad_request_handler(self, error):
        """Handle 400 Bad Request errors"""
        log_security_event('error_400', details=f"Bad request: {request.path}")
        return self._error_response(400, "Bad Request", "The server could not understand the request.")
    
    def unauthorized_handler(self, error):
        """Handle 401 Unauthorized errors"""
        log_security_event('error_401', details=f"Unauthorized: {request.path}")
        return self._error_response(401, "Unauthorized", "Authentication is required to access this resource.")
    
    def forbidden_handler(self, error):
        """Handle 403 Forbidden errors"""
        log_security_event('error_403', details=f"Forbidden: {request.path}")
        return self._error_response(403, "Forbidden", "You don't have permission to access this resource.")
    
    def not_found_handler(self, error):
        """Handle 404 Not Found errors"""
        log_security_event('error_404', details=f"Not found: {request.path}")
        return self._error_response(404, "Not Found", "The requested resource was not found on this server.")
    
    def too_many_requests_handler(self, error):
        """Handle 429 Too Many Requests errors"""
        log_security_event('error_429', details=f"Rate limit exceeded: {request.path}")
        return self._error_response(429, "Too Many Requests", "You have sent too many requests. Please try again later.")
    
    def server_error_handler(self, error):
        """Handle 500 Internal Server Error errors"""
        log_security_event('error_500', details=f"Server error: {request.path}, {str(error)}")
        return self._error_response(500, "Internal Server Error", "The server encountered an internal error.")
    
    def _error_response(self, status_code, title, message):
        """Generate consistent error responses"""
        if request.path.startswith('/api/'):
            # Return JSON for API requests
            return current_app.response_class(
                response=json.dumps({
                    'error': {
                        'code': status_code,
                        'title': title,
                        'message': message
                    }
                }),
                status=status_code,
                mimetype='application/json'
            )
        else:
            # Return HTML for browser requests
            return current_app.response_class(
                response=f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>{status_code} - {title}</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                        .error-container {{ max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                        h1 {{ color: #d9534f; }}
                    </style>
                </head>
                <body>
                    <div class="error-container">
                        <h1>{status_code} - {title}</h1>
                        <p>{message}</p>
                        <p><a href="/">Return to Home</a></p>
                    </div>
                </body>
                </html>
                """,
                status=status_code,
                mimetype='text/html'
            )

# Decorator for API rate limiting
def api_rate_limit(limit=15, period=60):
    """Decorator to apply rate limiting to API endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Create a unique key for this endpoint and IP
            key = f"{request.remote_addr}:{request.endpoint}"
            
            if is_rate_limited(key, limit=limit, period=period):
                log_security_event('api_rate_limit_exceeded', 
                                  details=f"API rate limit exceeded for IP: {request.remote_addr}, Endpoint: {request.endpoint}")
                abort(429)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Decorator for requiring API keys
def require_api_key(f):
    """Decorator to require API key for access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            log_security_event('api_key_missing', 
                              details=f"API key missing for endpoint: {request.endpoint}")
            abort(401)
        
        # In a real app, validate the API key against a database
        # For this demo, we'll use a hardcoded key
        valid_keys = ['test_api_key_1', 'test_api_key_2']
        
        if api_key not in valid_keys:
            log_security_event('api_key_invalid', 
                              details=f"Invalid API key used for endpoint: {request.endpoint}")
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function
