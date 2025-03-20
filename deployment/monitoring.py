"""
Monitoring and logging system for Stock Tracker Application
"""

import logging
import logging.handlers
import os
import time
import json
import socket
import threading
import queue
from datetime import datetime
from flask import request, g, current_app
from functools import wraps

# Configure base logging
if not os.path.exists('logs'):
    os.makedirs('logs')

# Create different log files for different types of events
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
security_handler = logging.handlers.RotatingFileHandler(
    'logs/security.log', maxBytes=10485760, backupCount=10)
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'))
security_logger.addHandler(security_handler)

# Performance logger
performance_logger = logging.getLogger('performance')
performance_logger.setLevel(logging.INFO)
performance_handler = logging.handlers.RotatingFileHandler(
    'logs/performance.log', maxBytes=10485760, backupCount=5)
performance_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'))
performance_logger.addHandler(performance_handler)

# User activity logger
activity_logger = logging.getLogger('activity')
activity_logger.setLevel(logging.INFO)
activity_handler = logging.handlers.RotatingFileHandler(
    'logs/activity.log', maxBytes=10485760, backupCount=10)
activity_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'))
activity_logger.addHandler(activity_handler)

# Error logger
error_logger = logging.getLogger('error')
error_logger.setLevel(logging.ERROR)
error_handler = logging.handlers.RotatingFileHandler(
    'logs/error.log', maxBytes=10485760, backupCount=10)
error_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s\n%(pathname)s:%(lineno)d\n%(message)s\n'))
error_logger.addHandler(error_handler)

# API logger
api_logger = logging.getLogger('api')
api_logger.setLevel(logging.INFO)
api_handler = logging.handlers.RotatingFileHandler(
    'logs/api.log', maxBytes=10485760, backupCount=5)
api_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'))
api_logger.addHandler(api_handler)

# Console handler for all logs during development
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
console_handler.setLevel(logging.INFO)

# Add console handler to all loggers
security_logger.addHandler(console_handler)
performance_logger.addHandler(console_handler)
activity_logger.addHandler(console_handler)
error_logger.addHandler(console_handler)
api_logger.addHandler(console_handler)

class MonitoringSystem:
    """Centralized monitoring system for the application"""
    
    def __init__(self, app=None):
        self.app = app
        self.log_queue = queue.Queue()
        self.alert_thresholds = {
            'login_failures': 5,  # Alert after 5 failed login attempts
            'api_errors': 10,     # Alert after 10 API errors in 5 minutes
            'response_time': 2.0  # Alert if response time exceeds 2 seconds
        }
        self.metrics = {
            'requests': 0,
            'errors': 0,
            'login_attempts': 0,
            'login_failures': 0,
            'api_calls': 0,
            'api_errors': 0,
            'average_response_time': 0.0,
            'active_users': set()
        }
        self.start_time = time.time()
        self.lock = threading.Lock()
        
        # Start background worker for processing logs
        self.worker_thread = threading.Thread(target=self._process_logs, daemon=True)
        self.worker_thread.start()
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize monitoring with Flask app"""
        self.app = app
        
        # Register before_request handler
        app.before_request(self._before_request)
        
        # Register after_request handler
        app.after_request(self._after_request)
        
        # Register teardown_request handler
        app.teardown_request(self._teardown_request)
        
        # Register error handler
        app.register_error_handler(Exception, self._log_exception)
        
        security_logger.info("Monitoring system initialized")
    
    def _before_request(self):
        """Process request before it reaches the view"""
        # Store request start time
        g.start_time = time.time()
        g.request_id = self._generate_request_id()
        
        # Log request
        self.log_queue.put({
            'logger': 'activity',
            'level': 'info',
            'message': f"Request started: {request.method} {request.path}",
            'data': {
                'request_id': g.request_id,
                'method': request.method,
                'path': request.path,
                'ip': request.remote_addr,
                'user_agent': request.user_agent.string,
                'user_id': self._get_user_id()
            }
        })
        
        # Update metrics
        with self.lock:
            self.metrics['requests'] += 1
            if request.path.startswith('/api/'):
                self.metrics['api_calls'] += 1
    
    def _after_request(self, response):
        """Process response before it's sent to the client"""
        # Calculate response time
        if hasattr(g, 'start_time'):
            response_time = time.time() - g.start_time
            
            # Update metrics
            with self.lock:
                # Update average response time using weighted average
                if self.metrics['requests'] > 1:
                    self.metrics['average_response_time'] = (
                        (self.metrics['average_response_time'] * (self.metrics['requests'] - 1) + response_time) / 
                        self.metrics['requests']
                    )
                else:
                    self.metrics['average_response_time'] = response_time
                
                # Check if response time exceeds threshold
                if response_time > self.alert_thresholds['response_time']:
                    self._trigger_alert('response_time', {
                        'request_path': request.path,
                        'response_time': response_time,
                        'threshold': self.alert_thresholds['response_time']
                    })
            
            # Log response
            self.log_queue.put({
                'logger': 'performance',
                'level': 'info',
                'message': f"Request completed: {request.method} {request.path} - {response.status_code} - {response_time:.4f}s",
                'data': {
                    'request_id': getattr(g, 'request_id', 'unknown'),
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'user_id': self._get_user_id()
                }
            })
            
            # Add response time header
            response.headers['X-Response-Time'] = f"{response_time:.4f}s"
        
        return response
    
    def _teardown_request(self, exception):
        """Clean up after request is processed"""
        if exception:
            # Log exception
            self.log_queue.put({
                'logger': 'error',
                'level': 'error',
                'message': f"Request failed: {request.method} {request.path} - {str(exception)}",
                'data': {
                    'request_id': getattr(g, 'request_id', 'unknown'),
                    'method': request.method,
                    'path': request.path,
                    'exception': str(exception),
                    'user_id': self._get_user_id()
                }
            })
            
            # Update metrics
            with self.lock:
                self.metrics['errors'] += 1
                if request.path.startswith('/api/'):
                    self.metrics['api_errors'] += 1
                    
                    # Check if API errors exceed threshold
                    if self.metrics['api_errors'] >= self.alert_thresholds['api_errors']:
                        self._trigger_alert('api_errors', {
                            'count': self.metrics['api_errors'],
                            'threshold': self.alert_thresholds['api_errors']
                        })
    
    def _log_exception(self, exception):
        """Log unhandled exceptions"""
        error_logger.exception(f"Unhandled exception: {str(exception)}")
        
        # Update metrics
        with self.lock:
            self.metrics['errors'] += 1
        
        # Return appropriate error response
        return self.app.response_class(
            response=json.dumps({
                'error': {
                    'message': 'An unexpected error occurred',
                    'code': 500
                }
            }),
            status=500,
            mimetype='application/json'
        )
    
    def log_security_event(self, event_type, details=None, user_id=None):
        """Log security-related events"""
        if user_id is None:
            user_id = self._get_user_id()
        
        self.log_queue.put({
            'logger': 'security',
            'level': 'info',
            'message': f"Security event: {event_type}",
            'data': {
                'event_type': event_type,
                'user_id': user_id,
                'ip_address': request.remote_addr if request else 'N/A',
                'user_agent': request.user_agent.string if request else 'N/A',
                'details': details
            }
        })
        
        # Update metrics for login attempts
        if event_type == 'login_attempt':
            with self.lock:
                self.metrics['login_attempts'] += 1
        
        # Update metrics for login failures
        if event_type == 'login_failure':
            with self.lock:
                self.metrics['login_failures'] += 1
                
                # Check if login failures exceed threshold
                if self.metrics['login_failures'] >= self.alert_thresholds['login_failures']:
                    self._trigger_alert('login_failures', {
                        'count': self.metrics['login_failures'],
                        'threshold': self.alert_thresholds['login_failures'],
                        'ip_address': request.remote_addr if request else 'N/A'
                    })
    
    def log_user_activity(self, activity_type, details=None, user_id=None):
        """Log user activity events"""
        if user_id is None:
            user_id = self._get_user_id()
        
        self.log_queue.put({
            'logger': 'activity',
            'level': 'info',
            'message': f"User activity: {activity_type}",
            'data': {
                'activity_type': activity_type,
                'user_id': user_id,
                'ip_address': request.remote_addr if request else 'N/A',
                'details': details
            }
        })
        
        # Update active users set
        if user_id:
            with self.lock:
                self.metrics['active_users'].add(user_id)
    
    def log_api_call(self, endpoint, method, status_code, response_time):
        """Log API call details"""
        self.log_queue.put({
            'logger': 'api',
            'level': 'info',
            'message': f"API call: {method} {endpoint} - {status_code} - {response_time:.4f}s",
            'data': {
                'endpoint': endpoint,
                'method': method,
                'status_code': status_code,
                'response_time': response_time,
                'user_id': self._get_user_id()
            }
        })
    
    def get_metrics(self):
        """Get current monitoring metrics"""
        with self.lock:
            uptime = time.time() - self.start_time
            return {
                'uptime': uptime,
                'uptime_formatted': self._format_uptime(uptime),
                'requests': self.metrics['requests'],
                'errors': self.metrics['errors'],
                'error_rate': (self.metrics['errors'] / self.metrics['requests']) * 100 if self.metrics['requests'] > 0 else 0,
                'login_attempts': self.metrics['login_attempts'],
                'login_failures': self.metrics['login_failures'],
                'api_calls': self.metrics['api_calls'],
                'api_errors': self.metrics['api_errors'],
                'average_response_time': self.metrics['average_response_time'],
                'active_users_count': len(self.metrics['active_users'])
            }
    
    def _process_logs(self):
        """Background worker to process logs from queue"""
        while True:
            try:
                # Get log entry from queue
                log_entry = self.log_queue.get(timeout=1.0)
                
                # Get appropriate logger
                logger_name = log_entry.get('logger', 'activity')
                if logger_name == 'security':
                    logger = security_logger
                elif logger_name == 'performance':
                    logger = performance_logger
                elif logger_name == 'error':
                    logger = error_logger
                elif logger_name == 'api':
                    logger = api_logger
                else:
                    logger = activity_logger
                
                # Get log level
                level = log_entry.get('level', 'info').lower()
                
                # Format message with data if available
                message = log_entry.get('message', '')
                data = log_entry.get('data')
                if data:
                    message = f"{message} - {json.dumps(data)}"
                
                # Log message with appropriate level
                if level == 'debug':
                    logger.debug(message)
                elif level == 'info':
                    logger.info(message)
                elif level == 'warning':
                    logger.warning(message)
                elif level == 'error':
                    logger.error(message)
                elif level == 'critical':
                    logger.critical(message)
                
                # Mark task as done
                self.log_queue.task_done()
            except queue.Empty:
                # Queue is empty, continue
                continue
            except Exception as e:
                # Log error and continue
                print(f"Error processing log entry: {str(e)}")
                continue
    
    def _trigger_alert(self, alert_type, data):
        """Trigger an alert when thresholds are exceeded"""
        # Log alert
        security_logger.warning(f"ALERT: {alert_type} threshold exceeded - {json.dumps(data)}")
        
        # In a real application, you would send notifications via email, SMS, etc.
        # For this demo, we'll just log the alert
    
    def _generate_request_id(self):
        """Generate a unique request ID"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        random_part = os.urandom(4).hex()
        return f"{timestamp}-{random_part}"
    
    def _get_user_id(self):
        """Get current user ID if available"""
        from flask_login import current_user
        if current_user and current_user.is_authenticated:
            return current_user.id
        return None
    
    def _format_uptime(self, seconds):
        """Format uptime in human-readable format"""
        days, remainder = divmod(seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        parts = []
        if days > 0:
            parts.append(f"{int(days)} days")
        if hours > 0:
            parts.append(f"{int(hours)} hours")
        if minutes > 0:
            parts.append(f"{int(minutes)} minutes")
        if seconds > 0 or not parts:
            parts.append(f"{int(seconds)} seconds")
        
        return ", ".join(parts)

# Create a global instance for use throughout the application
monitoring_system = None

def init_monitoring(app):
    """Initialize the monitoring system"""
    global monitoring_system
    monitoring_system = MonitoringSystem(app)
    return monitoring_system

# Decorator for monitoring API endpoints
def monitor_api(f):
    """Decorator to monitor API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        # Call the original function
        response = f(*args, **kwargs)
        
        # Calculate response time
        response_time = time.time() - start_time
        
        # Get status code
        if hasattr(response, 'status_code'):
            status_code = response.status_code
        else:
            # For jsonify responses
            status_code = 200
        
        # Log API call
        if monitoring_system:
            monitoring_system.log_api_call(
                endpoint=request.path,
                method=request.method,
                status_code=status_code,
                response_time=response_time
            )
        
        return response
    return decorated_function

# Convenience functions
def log_security_event(event_type, details=None, user_id=None):
    """Log security event using the global monitoring system"""
    if monitoring_system:
        monitoring_system.log_security_event(event_type, details, user_id)

def log_user_activity(activity_type, details=None, user_id=None):
    """Log user activity using the global monitoring system"""
    if monitoring_system:
        monitoring_system.log_user_activity(activity_type, details, user_id)

def get_metrics():
    """Get metrics from the global monitoring system"""
    if monitoring_system:
        return monitoring_system.get_metrics()
    return {}
