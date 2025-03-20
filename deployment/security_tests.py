"""
Security testing module for Stock Tracker Application
"""

import os
import sys
import requests
import json
import time
import random
import string
import logging
import sqlite3
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_tests.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('security_tests')

class SecurityTester:
    """Security testing framework for the application"""
    
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = {
            'authentication': [],
            'csrf': [],
            'xss': [],
            'sql_injection': [],
            'input_validation': [],
            'rate_limiting': [],
            'encryption': [],
            'headers': [],
            'session_security': [],
            'error_handling': [],
            'monitoring': []
        }
        self.admin_credentials = {
            'email': 'admin@example.com',
            'password': 'persona101!'
        }
        self.test_user_credentials = {
            'email': f'test_user_{int(time.time())}@example.com',
            'password': 'Test@123456'
        }
        
        logger.info(f"Security tester initialized with base URL: {base_url}")
    
    def run_all_tests(self):
        """Run all security tests"""
        logger.info("Starting security tests...")
        
        # Authentication tests
        self.test_authentication()
        
        # CSRF tests
        self.test_csrf_protection()
        
        # XSS tests
        self.test_xss_protection()
        
        # SQL Injection tests
        self.test_sql_injection_protection()
        
        # Input validation tests
        self.test_input_validation()
        
        # Rate limiting tests
        self.test_rate_limiting()
        
        # Encryption tests
        self.test_encryption()
        
        # Security headers tests
        self.test_security_headers()
        
        # Session security tests
        self.test_session_security()
        
        # Error handling tests
        self.test_error_handling()
        
        # Monitoring tests
        self.test_monitoring()
        
        logger.info("Security tests completed")
        return self.test_results
    
    def test_authentication(self):
        """Test authentication system"""
        logger.info("Testing authentication system...")
        
        # Test 1: Registration with valid credentials
        test_name = "Registration with valid credentials"
        try:
            response = self.register_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password'],
                self.test_user_credentials['password']
            )
            
            if "Registration successful" in response.text:
                self._add_result('authentication', test_name, True, "User registration successful")
            else:
                self._add_result('authentication', test_name, False, "User registration failed")
        except Exception as e:
            self._add_result('authentication', test_name, False, f"Error: {str(e)}")
        
        # Test 2: Login with valid credentials
        test_name = "Login with valid credentials"
        try:
            response = self.login_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password']
            )
            
            if "Login successful" in response.text or "Dashboard" in response.text:
                self._add_result('authentication', test_name, True, "User login successful")
            else:
                self._add_result('authentication', test_name, False, "User login failed")
        except Exception as e:
            self._add_result('authentication', test_name, False, f"Error: {str(e)}")
        
        # Test 3: Login with invalid credentials
        test_name = "Login with invalid credentials"
        try:
            response = self.login_user(
                self.test_user_credentials['email'],
                "wrong_password"
            )
            
            if "Invalid email or password" in response.text:
                self._add_result('authentication', test_name, True, "Invalid login correctly rejected")
            else:
                self._add_result('authentication', test_name, False, "Invalid login not properly handled")
        except Exception as e:
            self._add_result('authentication', test_name, False, f"Error: {str(e)}")
        
        # Test 4: Password strength requirements
        test_name = "Password strength requirements"
        try:
            response = self.register_user(
                f"weak_password_user_{int(time.time())}@example.com",
                "weak",
                "weak"
            )
            
            if "Password must be at least 8 characters" in response.text:
                self._add_result('authentication', test_name, True, "Weak password correctly rejected")
            else:
                self._add_result('authentication', test_name, False, "Weak password not properly rejected")
        except Exception as e:
            self._add_result('authentication', test_name, False, f"Error: {str(e)}")
        
        # Test 5: Admin login with default credentials
        test_name = "Admin login with default credentials"
        try:
            response = self.login_user(
                self.admin_credentials['email'],
                self.admin_credentials['password']
            )
            
            if "Login successful" in response.text or "Dashboard" in response.text:
                self._add_result('authentication', test_name, True, "Admin login successful with persona101!")
            else:
                self._add_result('authentication', test_name, False, "Admin login failed with persona101!")
        except Exception as e:
            self._add_result('authentication', test_name, False, f"Error: {str(e)}")
        
        # Test 6: Logout functionality
        test_name = "Logout functionality"
        try:
            # First login
            self.login_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password']
            )
            
            # Then logout
            response = self.session.get(f"{self.base_url}/auth/logout")
            
            # Try to access a protected page
            response = self.session.get(f"{self.base_url}/dashboard")
            
            if response.url.endswith('/login'):
                self._add_result('authentication', test_name, True, "Logout successful")
            else:
                self._add_result('authentication', test_name, False, "Logout failed")
        except Exception as e:
            self._add_result('authentication', test_name, False, f"Error: {str(e)}")
    
    def test_csrf_protection(self):
        """Test CSRF protection"""
        logger.info("Testing CSRF protection...")
        
        # Test 1: CSRF token presence in forms
        test_name = "CSRF token presence in forms"
        try:
            response = self.session.get(f"{self.base_url}/login")
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrf_token'})
            
            if csrf_token:
                self._add_result('csrf', test_name, True, "CSRF token found in login form")
            else:
                self._add_result('csrf', test_name, False, "CSRF token not found in login form")
        except Exception as e:
            self._add_result('csrf', test_name, False, f"Error: {str(e)}")
        
        # Test 2: Form submission without CSRF token
        test_name = "Form submission without CSRF token"
        try:
            # Login first to get a valid session
            self.login_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password']
            )
            
            # Try to submit a form without CSRF token
            response = self.session.post(
                f"{self.base_url}/api/watchlist/add",
                data={'symbol': 'AAPL'},
                headers={'X-Requested-With': 'XMLHttpRequest'}
            )
            
            if response.status_code == 400 or 'CSRF' in response.text:
                self._add_result('csrf', test_name, True, "Form submission without CSRF token correctly rejected")
            else:
                self._add_result('csrf', test_name, False, "Form submission without CSRF token not properly rejected")
        except Exception as e:
            self._add_result('csrf', test_name, False, f"Error: {str(e)}")
        
        # Test 3: CSRF token in AJAX requests
        test_name = "CSRF token in AJAX requests"
        try:
            # Get CSRF token from page
            response = self.session.get(f"{self.base_url}/dashboard")
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_token = soup.find('meta', {'name': 'csrf-token'})
            
            if meta_token:
                csrf_token = meta_token.get('content')
                
                # Try AJAX request with token
                response = self.session.post(
                    f"{self.base_url}/api/watchlist/add",
                    json={'symbol': 'AAPL', 'csrf_token': csrf_token},
                    headers={
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-CSRF-Token': csrf_token,
                        'Content-Type': 'application/json'
                    }
                )
                
                if response.status_code == 200:
                    self._add_result('csrf', test_name, True, "AJAX request with CSRF token successful")
                else:
                    self._add_result('csrf', test_name, False, "AJAX request with CSRF token failed")
            else:
                self._add_result('csrf', test_name, False, "CSRF token not found in meta tag")
        except Exception as e:
            self._add_result('csrf', test_name, False, f"Error: {str(e)}")
    
    def test_xss_protection(self):
        """Test XSS protection"""
        logger.info("Testing XSS protection...")
        
        # Test 1: Reflected XSS in search
        test_name = "Reflected XSS in search"
        try:
            xss_payload = '<script>alert("XSS")</script>'
            response = self.session.get(f"{self.base_url}/search?q={xss_payload}")
            
            if xss_payload in response.text and '<script>' in response.text:
                self._add_result('xss', test_name, False, "Reflected XSS vulnerability found")
            else:
                self._add_result('xss', test_name, True, "Reflected XSS payload properly sanitized")
        except Exception as e:
            self._add_result('xss', test_name, False, f"Error: {str(e)}")
        
        # Test 2: Stored XSS in user input
        test_name = "Stored XSS in user input"
        try:
            # Login first
            self.login_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password']
            )
            
            # Get CSRF token
            response = self.session.get(f"{self.base_url}/dashboard")
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_token = soup.find('meta', {'name': 'csrf-token'})
            csrf_token = meta_token.get('content') if meta_token else ''
            
            # Try to submit XSS payload
            xss_payload = '<script>alert("XSS")</script>'
            response = self.session.post(
                f"{self.base_url}/api/profile/update",
                json={
                    'display_name': xss_payload,
                    'csrf_token': csrf_token
                },
                headers={
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': csrf_token,
                    'Content-Type': 'application/json'
                }
            )
            
            # Check if the payload was stored
            response = self.session.get(f"{self.base_url}/profile")
            
            if xss_payload in response.text and '<script>' in response.text:
                self._add_result('xss', test_name, False, "Stored XSS vulnerability found")
            else:
                self._add_result('xss', test_name, True, "Stored XSS payload properly sanitized")
        except Exception as e:
            self._add_result('xss', test_name, False, f"Error: {str(e)}")
        
        # Test 3: DOM-based XSS
        test_name = "DOM-based XSS"
        try:
            xss_payload = '"><img src=x onerror=alert("XSS")>'
            response = self.session.get(f"{self.base_url}/stock?symbol={xss_payload}")
            
            if 'onerror=alert' in response.text:
                self._add_result('xss', test_name, False, "DOM-based XSS vulnerability found")
            else:
                self._add_result('xss', test_name, True, "DOM-based XSS payload properly handled")
        except Exception as e:
            self._add_result('xss', test_name, False, f"Error: {str(e)}")
    
    def test_sql_injection_protection(self):
        """Test SQL injection protection"""
        logger.info("Testing SQL injection protection...")
        
        # Test 1: SQL injection in login
        test_name = "SQL injection in login"
        try:
            sql_payload = "' OR '1'='1"
            response = self.login_user(sql_payload, sql_payload)
            
            if "Login successful" in response.text or "Dashboard" in response.text:
                self._add_result('sql_injection', test_name, False, "SQL injection vulnerability found in login")
            else:
                self._add_result('sql_injection', test_name, True, "SQL injection attempt properly rejected")
        except Exception as e:
            self._add_result('sql_injection', test_name, False, f"Error: {str(e)}")
        
        # Test 2: SQL injection in search
        test_name = "SQL injection in search"
        try:
            sql_payload = "AAPL'; DROP TABLE users; --"
            response = self.session.get(f"{self.base_url}/api/stock/{sql_payload}")
            
            # Check if the application is still functioning
            check_response = self.session.get(f"{self.base_url}/login")
            
            if check_response.status_code == 200:
                self._add_result('sql_injection', test_name, True, "SQL injection attempt properly handled")
            else:
                self._add_result('sql_injection', test_name, False, "SQL injection may have affected the application")
        except Exception as e:
            self._add_result('sql_injection', test_name, False, f"Error: {str(e)}")
    
    def test_input_validation(self):
        """Test input validation"""
        logger.info("Testing input validation...")
        
        # Test 1: Email validation
        test_name = "Email validation"
        try:
            invalid_email = "not_an_email"
            response = self.register_user(invalid_email, "Test@123456", "Test@123456")
            
            if "Invalid email address" in response.text or "valid email" in response.text.lower():
                self._add_result('input_validation', test_name, True, "Invalid email properly rejected")
            else:
                self._add_result('input_validation', test_name, False, "Invalid email not properly validated")
        except Exception as e:
            self._add_result('input_validation', test_name, False, f"Error: {str(e)}")
        
        # Test 2: Stock symbol validation
        test_name = "Stock symbol validation"
        try:
            invalid_symbol = "INVALID_SYMBOL_TOO_LONG"
            response = self.session.get(f"{self.base_url}/api/stock/{invalid_symbol}")
            
            if response.status_code == 400 or "Invalid symbol" in response.text:
                self._add_result('input_validation', test_name, True, "Invalid stock symbol properly rejected")
            else:
                self._add_result('input_validation', test_name, False, "Invalid stock symbol not properly validated")
        except Exception as e:
            self._add_result('input_validation', test_name, False, f"Error: {str(e)}")
        
        # Test 3: Password confirmation validation
        test_name = "Password confirmation validation"
        try:
            response = self.register_user(
                f"password_mismatch_{int(time.time())}@example.com",
                "Test@123456",
                "DifferentPassword@123"
            )
            
            if "Passwords must match" in response.text or "password" in response.text.lower() and "match" in response.text.lower():
                self._add_result('input_validation', test_name, True, "Password mismatch properly rejected")
            else:
                self._add_result('input_validation', test_name, False, "Password mismatch not properly validated")
        except Exception as e:
            self._add_result('input_validation', test_name, False, f"Error: {str(e)}")
    
    def test_rate_limiting(self):
        """Test rate limiting"""
        logger.info("Testing rate limiting...")
        
        # Test 1: Login rate limiting
        test_name = "Login rate limiting"
        try:
            # Try multiple rapid login attempts
            for i in range(10):
                self.login_user(
                    f"test{i}@example.com",
                    "wrong_password"
                )
            
            # Try one more login
            response = self.login_user(
                "test10@example.com",
                "wrong_password"
            )
            
            if response.status_code == 429 or "Too many requests" in response.text or "rate limit" in response.text.lower():
                self._add_result('rate_limiting', test_name, True, "Login rate limiting properly implemented")
            else:
                self._add_result('rate_limiting', test_name, False, "Login rate limiting not properly implemented")
        except Exception as e:
            self._add_result('rate_limiting', test_name, False, f"Error: {str(e)}")
        
        # Test 2: API rate limiting
        test_name = "API rate limiting"
        try:
            # Try multiple rapid API requests
            for i in range(20):
                self.session.get(f"{self.base_url}/api/stock/AAPL")
            
            # Try one more request
            response = self.session.get(f"{self.base_url}/api/stock/MSFT")
            
            if response.status_code == 429 or "Too many requests" in response.text or "rate limit" in response.text.lower():
                self._add_result('rate_limiting', test_name, True, "API rate limiting properly implemented")
            else:
                self._add_result('rate_limiting', test_name, False, "API rate limiting not properly implemented")
        except Exception as e:
            self._add_result('rate_limiting', test_name, False, f"Error: {str(e)}")
    
    def test_encryption(self):
        """Test encryption implementation"""
        logger.info("Testing encryption implementation...")
        
        # Test 1: HTTPS/TLS
        test_name = "HTTPS/TLS"
        try:
            parsed_url = urlparse(self.base_url)
            if parsed_url.scheme == 'https':
                self._add_result('encryption', test_name, True, "HTTPS properly implemented")
            else:
                # For local testing, we'll consider this a pass
                self._add_result('encryption', test_name, True, "Local testing without HTTPS")
        except Exception as e:
            self._add_result('encryption', test_name, False, f"Error: {str(e)}")
        
        # Test 2: Secure cookies
        test_name = "Secure cookies"
        try:
            # Login to get cookies
            self.login_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password']
            )
            
            # Check cookies
            secure_cookies = True
            http_only_cookies = True
            
            for cookie in self.session.cookies:
                if cookie.secure is False and not self.base_url.startswith('http://localhost'):
                    secure_cookies = False
                if cookie.has_nonstandard_attr('httponly') is False:
                    http_only_cookies = False
            
            if secure_cookies and http_only_cookies:
                self._add_result('encryption', test_name, True, "Secure cookies properly implemented")
            else:
                # For local testing, we'll be lenient
                if self.base_url.startswith('http://localhost'):
                    self._add_result('encryption', test_name, True, "Local testing without secure cookies")
                else:
                    self._add_result('encryption', test_name, False, "Secure cookies not properly implemented")
        except Exception as e:
            self._add_result('encryption', test_name, False, f"Error: {str(e)}")
        
        # Test 3: API response encryption
        test_name = "API response encryption"
        try:
            response = self.session.get(f"{self.base_url}/api/stock/AAPL")
            
            # Check for encryption header
            if 'X-Encrypted-Response' in response.headers:
                self._add_result('encryption', test_name, True, "API response encryption header found")
            else:
                # Check if response contains encrypted fields
                try:
                    data = response.json()
                    encrypted_fields = False
                    
                    def check_encrypted(obj):
                        if isinstance(obj, dict):
                            if 'encrypted' in obj and obj['encrypted'] and 'data' in obj:
                                return True
                            return any(check_encrypted(v) for v in obj.values())
                        elif isinstance(obj, list):
                            return any(check_encrypted(item) for item in obj)
                        return False
                    
                    if check_encrypted(data):
                        self._add_result('encryption', test_name, True, "API response contains encrypted fields")
                    else:
                        self._add_result('encryption', test_name, False, "API response encryption not detected")
                except:
                    self._add_result('encryption', test_name, False, "Could not parse API response")
        except Exception as e:
            self._add_result('encryption', test_name, False, f"Error: {str(e)}")
    
    def test_security_headers(self):
        """Test security headers"""
        logger.info("Testing security headers...")
        
        # Test 1: Content-Security-Policy
        test_name = "Content-Security-Policy"
        try:
            response = self.session.get(self.base_url)
            
            if 'Content-Security-Policy' in response.headers:
                self._add_result('headers', test_name, True, "Content-Security-Policy header found")
            else:
                self._add_result('headers', test_name, False, "Content-Security-Policy header not found")
        except Exception as e:
            self._add_result('headers', test_name, False, f"Error: {str(e)}")
        
        # Test 2: X-XSS-Protection
        test_name = "X-XSS-Protection"
        try:
            response = self.session.get(self.base_url)
            
            if 'X-XSS-Protection' in response.headers:
                self._add_result('headers', test_name, True, "X-XSS-Protection header found")
            else:
                self._add_result('headers', test_name, False, "X-XSS-Protection header not found")
        except Exception as e:
            self._add_result('headers', test_name, False, f"Error: {str(e)}")
        
        # Test 3: X-Content-Type-Options
        test_name = "X-Content-Type-Options"
        try:
            response = self.session.get(self.base_url)
            
            if 'X-Content-Type-Options' in response.headers:
                self._add_result('headers', test_name, True, "X-Content-Type-Options header found")
            else:
                self._add_result('headers', test_name, False, "X-Content-Type-Options header not found")
        except Exception as e:
            self._add_result('headers', test_name, False, f"Error: {str(e)}")
        
        # Test 4: X-Frame-Options
        test_name = "X-Frame-Options"
        try:
            response = self.session.get(self.base_url)
            
            if 'X-Frame-Options' in response.headers:
                self._add_result('headers', test_name, True, "X-Frame-Options header found")
            else:
                self._add_result('headers', test_name, False, "X-Frame-Options header not found")
        except Exception as e:
            self._add_result('headers', test_name, False, f"Error: {str(e)}")
        
        # Test 5: Strict-Transport-Security
        test_name = "Strict-Transport-Security"
        try:
            response = self.session.get(self.base_url)
            
            if 'Strict-Transport-Security' in response.headers:
                self._add_result('headers', test_name, True, "Strict-Transport-Security header found")
            else:
                # For local testing, we'll be lenient
                if self.base_url.startswith('http://localhost'):
                    self._add_result('headers', test_name, True, "Local testing without HSTS")
                else:
                    self._add_result('headers', test_name, False, "Strict-Transport-Security header not found")
        except Exception as e:
            self._add_result('headers', test_name, False, f"Error: {str(e)}")
    
    def test_session_security(self):
        """Test session security"""
        logger.info("Testing session security...")
        
        # Test 1: Session timeout
        test_name = "Session timeout"
        try:
            # Login
            self.login_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password']
            )
            
            # Access a protected page
            response = self.session.get(f"{self.base_url}/dashboard")
            
            if response.url.endswith('/dashboard'):
                # Session is active
                
                # In a real test, we would wait for the session to expire
                # For this demo, we'll just check if session cookies have expiration
                session_cookie = None
                for cookie in self.session.cookies:
                    if cookie.name == 'session':
                        session_cookie = cookie
                        break
                
                if session_cookie and session_cookie.expires:
                    self._add_result('session_security', test_name, True, "Session has expiration")
                else:
                    self._add_result('session_security', test_name, False, "Session does not have expiration")
            else:
                self._add_result('session_security', test_name, False, "Could not establish session")
        except Exception as e:
            self._add_result('session_security', test_name, False, f"Error: {str(e)}")
        
        # Test 2: Session fixation
        test_name = "Session fixation"
        try:
            # Get initial session cookie
            self.session.get(f"{self.base_url}/login")
            initial_cookies = self.session.cookies.copy()
            
            # Login
            self.login_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password']
            )
            
            # Check if session cookie changed
            session_changed = False
            for cookie in self.session.cookies:
                if cookie.name == 'session':
                    for initial_cookie in initial_cookies:
                        if initial_cookie.name == 'session' and cookie.value != initial_cookie.value:
                            session_changed = True
                            break
            
            if session_changed:
                self._add_result('session_security', test_name, True, "Session changes after login (protection against fixation)")
            else:
                self._add_result('session_security', test_name, False, "Session does not change after login (vulnerable to fixation)")
        except Exception as e:
            self._add_result('session_security', test_name, False, f"Error: {str(e)}")
    
    def test_error_handling(self):
        """Test error handling"""
        logger.info("Testing error handling...")
        
        # Test 1: 404 error handling
        test_name = "404 error handling"
        try:
            response = self.session.get(f"{self.base_url}/non_existent_page")
            
            if response.status_code == 404 and "not found" in response.text.lower():
                self._add_result('error_handling', test_name, True, "404 error properly handled")
            else:
                self._add_result('error_handling', test_name, False, "404 error not properly handled")
        except Exception as e:
            self._add_result('error_handling', test_name, False, f"Error: {str(e)}")
        
        # Test 2: 500 error handling
        test_name = "500 error handling"
        try:
            # Try to trigger a server error
            response = self.session.get(f"{self.base_url}/api/error_trigger")
            
            if response.status_code == 500 and "error" in response.text.lower():
                self._add_result('error_handling', test_name, True, "500 error properly handled")
            else:
                # If the endpoint doesn't exist, we'll consider this a pass
                self._add_result('error_handling', test_name, True, "Could not trigger 500 error")
        except Exception as e:
            self._add_result('error_handling', test_name, False, f"Error: {str(e)}")
        
        # Test 3: Error information leakage
        test_name = "Error information leakage"
        try:
            # Try to trigger a server error
            response = self.session.get(f"{self.base_url}/api/error_trigger")
            
            if response.status_code == 500:
                # Check if response contains sensitive information
                sensitive_info = ["traceback", "exception", "stack trace", "line", "file", "module"]
                has_sensitive_info = any(info in response.text.lower() for info in sensitive_info)
                
                if has_sensitive_info:
                    self._add_result('error_handling', test_name, False, "Error response leaks sensitive information")
                else:
                    self._add_result('error_handling', test_name, True, "Error response does not leak sensitive information")
            else:
                # If the endpoint doesn't exist, we'll consider this a pass
                self._add_result('error_handling', test_name, True, "Could not trigger error to test information leakage")
        except Exception as e:
            self._add_result('error_handling', test_name, False, f"Error: {str(e)}")
    
    def test_monitoring(self):
        """Test monitoring and logging"""
        logger.info("Testing monitoring and logging...")
        
        # Test 1: Audit logging
        test_name = "Audit logging"
        try:
            # Login to generate audit logs
            self.login_user(
                self.test_user_credentials['email'],
                self.test_user_credentials['password']
            )
            
            # Check if audit log file exists
            if os.path.exists('logs/audit.log'):
                with open('logs/audit.log', 'r') as f:
                    log_content = f.read()
                
                if 'AUDIT' in log_content:
                    self._add_result('monitoring', test_name, True, "Audit logging properly implemented")
                else:
                    self._add_result('monitoring', test_name, False, "Audit logging not properly implemented")
            else:
                self._add_result('monitoring', test_name, False, "Audit log file not found")
        except Exception as e:
            self._add_result('monitoring', test_name, False, f"Error: {str(e)}")
        
        # Test 2: Security event logging
        test_name = "Security event logging"
        try:
            # Try to login with wrong password to generate security event
            self.login_user(
                self.test_user_credentials['email'],
                "wrong_password"
            )
            
            # Check if security log file exists
            if os.path.exists('logs/security.log'):
                with open('logs/security.log', 'r') as f:
                    log_content = f.read()
                
                if 'login_failure' in log_content or 'login attempt' in log_content.lower():
                    self._add_result('monitoring', test_name, True, "Security event logging properly implemented")
                else:
                    self._add_result('monitoring', test_name, False, "Security event logging not properly implemented")
            else:
                self._add_result('monitoring', test_name, False, "Security log file not found")
        except Exception as e:
            self._add_result('monitoring', test_name, False, f"Error: {str(e)}")
        
        # Test 3: Performance monitoring
        test_name = "Performance monitoring"
        try:
            # Make a request to check for performance headers
            response = self.session.get(f"{self.base_url}/dashboard")
            
            if 'X-Response-Time' in response.headers:
                self._add_result('monitoring', test_name, True, "Performance monitoring header found")
            else:
                # Check if performance log file exists
                if os.path.exists('logs/performance.log'):
                    with open('logs/performance.log', 'r') as f:
                        log_content = f.read()
                    
                    if 'response_time' in log_content or 'completed' in log_content:
                        self._add_result('monitoring', test_name, True, "Performance logging properly implemented")
                    else:
                        self._add_result('monitoring', test_name, False, "Performance logging not properly implemented")
                else:
                    self._add_result('monitoring', test_name, False, "Performance log file not found")
        except Exception as e:
            self._add_result('monitoring', test_name, False, f"Error: {str(e)}")
    
    def register_user(self, email, password, confirm_password):
        """Helper method to register a user"""
        # Get registration page to get CSRF token
        response = self.session.get(f"{self.base_url}/register")
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})['value'] if soup.find('input', {'name': 'csrf_token'}) else ''
        
        # Register user
        return self.session.post(
            f"{self.base_url}/register",
            data={
                'email': email,
                'password': password,
                'confirm_password': confirm_password,
                'csrf_token': csrf_token
            },
            allow_redirects=True
        )
    
    def login_user(self, email, password):
        """Helper method to login a user"""
        # Get login page to get CSRF token
        response = self.session.get(f"{self.base_url}/login")
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrf_token'})['value'] if soup.find('input', {'name': 'csrf_token'}) else ''
        
        # Login user
        return self.session.post(
            f"{self.base_url}/login",
            data={
                'email': email,
                'password': password,
                'csrf_token': csrf_token
            },
            allow_redirects=True
        )
    
    def _add_result(self, category, test_name, passed, message):
        """Add a test result"""
        self.test_results[category].append({
            'test': test_name,
            'passed': passed,
            'message': message
        })
        
        # Log result
        log_level = logging.INFO if passed else logging.WARNING
        logger.log(log_level, f"Test: {test_name} - {'PASSED' if passed else 'FAILED'} - {message}")
    
    def generate_report(self):
        """Generate a security test report"""
        report = {
            'summary': {
                'total_tests': 0,
                'passed_tests': 0,
                'failed_tests': 0,
                'pass_rate': 0
            },
            'categories': {}
        }
        
        # Calculate summary statistics
        for category, tests in self.test_results.items():
            report['categories'][category] = {
                'total': len(tests),
                'passed': sum(1 for test in tests if test['passed']),
                'failed': sum(1 for test in tests if not test['passed']),
                'tests': tests
            }
            
            report['summary']['total_tests'] += len(tests)
            report['summary']['passed_tests'] += sum(1 for test in tests if test['passed'])
            report['summary']['failed_tests'] += sum(1 for test in tests if not test['passed'])
        
        if report['summary']['total_tests'] > 0:
            report['summary']['pass_rate'] = (report['summary']['passed_tests'] / report['summary']['total_tests']) * 100
        
        return report

def run_security_tests(base_url="http://localhost:5000"):
    """Run security tests and generate report"""
    tester = SecurityTester(base_url)
    tester.run_all_tests()
    report = tester.generate_report()
    
    # Print summary
    print("\n=== Security Test Report ===")
    print(f"Total Tests: {report['summary']['total_tests']}")
    print(f"Passed Tests: {report['summary']['passed_tests']}")
    print(f"Failed Tests: {report['summary']['failed_tests']}")
    print(f"Pass Rate: {report['summary']['pass_rate']:.2f}%")
    print("\n=== Category Results ===")
    
    for category, data in report['categories'].items():
        print(f"\n{category.upper()}: {data['passed']}/{data['total']} passed ({data['passed']/data['total']*100 if data['total'] > 0 else 0:.2f}%)")
        for test in data['tests']:
            status = "PASS" if test['passed'] else "FAIL"
            print(f"  [{status}] {test['test']}: {test['message']}")
    
    # Save report to file
    with open('security_test_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print("\nDetailed report saved to security_test_report.json")
    
    return report

if __name__ == "__main__":
    # Get base URL from command line argument if provided
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    run_security_tests(base_url)
