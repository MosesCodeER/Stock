"""
Audit logging system for Stock Tracker Application
"""

import logging
import json
import os
from datetime import datetime
from flask import request, g, current_app
from flask_login import current_user
import sqlite3
from functools import wraps

# Configure audit logging
if not os.path.exists('logs'):
    os.makedirs('logs')

# Create audit logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_handler = logging.handlers.RotatingFileHandler(
    'logs/audit.log', maxBytes=10485760, backupCount=20)
audit_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'))
audit_logger.addHandler(audit_handler)

# Add console handler for development
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
console_handler.setLevel(logging.INFO)
audit_logger.addHandler(console_handler)

class AuditLogger:
    """Audit logging system for tracking user actions"""
    
    def __init__(self, app=None, db_path='audit.db'):
        self.app = app
        self.db_path = db_path
        
        # Initialize database
        self._init_db()
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize audit logger with Flask app"""
        self.app = app
        
        # Store db_path from app config if available
        if app.config.get('AUDIT_DB_PATH'):
            self.db_path = app.config.get('AUDIT_DB_PATH')
            self._init_db()
        
        audit_logger.info("Audit logging system initialized")
    
    def _init_db(self):
        """Initialize audit database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create audit log table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    details TEXT,
                    status TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
            audit_logger.info(f"Audit database initialized at {self.db_path}")
        except Exception as e:
            audit_logger.error(f"Error initializing audit database: {str(e)}")
    
    def log_action(self, action, resource=None, details=None, status='success', user_id=None):
        """Log a user action to both file and database"""
        # Get user ID if not provided
        if user_id is None:
            if current_user and current_user.is_authenticated:
                user_id = current_user.id
            else:
                user_id = 'anonymous'
        
        # Get request details if available
        ip_address = request.remote_addr if request else 'N/A'
        user_agent = request.user_agent.string if request and request.user_agent else 'N/A'
        
        # Create log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'action': action,
            'resource': resource,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'details': details,
            'status': status
        }
        
        # Log to file
        audit_logger.info(f"AUDIT: {json.dumps(log_entry)}")
        
        # Log to database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO audit_log (timestamp, user_id, action, resource, ip_address, user_agent, details, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_entry['timestamp'],
                log_entry['user_id'],
                log_entry['action'],
                log_entry['resource'],
                log_entry['ip_address'],
                log_entry['user_agent'],
                json.dumps(log_entry['details']) if log_entry['details'] else None,
                log_entry['status']
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            audit_logger.error(f"Error logging to audit database: {str(e)}")
    
    def get_audit_logs(self, user_id=None, action=None, start_date=None, end_date=None, limit=100):
        """Retrieve audit logs with optional filtering"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # Return rows as dictionaries
            cursor = conn.cursor()
            
            # Build query with filters
            query = "SELECT * FROM audit_log WHERE 1=1"
            params = []
            
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            
            if action:
                query += " AND action = ?"
                params.append(action)
            
            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)
            
            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            # Execute query
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            logs = []
            for row in rows:
                log = dict(row)
                # Parse details JSON if present
                if log['details']:
                    try:
                        log['details'] = json.loads(log['details'])
                    except:
                        pass
                logs.append(log)
            
            conn.close()
            return logs
        except Exception as e:
            audit_logger.error(f"Error retrieving audit logs: {str(e)}")
            return []
    
    def get_user_activity(self, user_id, limit=50):
        """Get recent activity for a specific user"""
        return self.get_audit_logs(user_id=user_id, limit=limit)
    
    def get_resource_activity(self, resource, limit=50):
        """Get recent activity for a specific resource"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT * FROM audit_log WHERE resource LIKE ? ORDER BY timestamp DESC LIMIT ?",
                (f"%{resource}%", limit)
            )
            
            rows = cursor.fetchall()
            
            # Convert rows to dictionaries
            logs = []
            for row in rows:
                log = dict(row)
                # Parse details JSON if present
                if log['details']:
                    try:
                        log['details'] = json.loads(log['details'])
                    except:
                        pass
                logs.append(log)
            
            conn.close()
            return logs
        except Exception as e:
            audit_logger.error(f"Error retrieving resource activity: {str(e)}")
            return []

# Create a global instance for use throughout the application
audit_logger_instance = None

def init_audit_logger(app):
    """Initialize the audit logger"""
    global audit_logger_instance
    audit_logger_instance = AuditLogger(app)
    return audit_logger_instance

# Decorator for auditing function calls
def audit_action(action, get_resource=None):
    """Decorator to audit function calls"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine resource if function provided
            resource = None
            if get_resource:
                try:
                    resource = get_resource(*args, **kwargs)
                except:
                    resource = None
            
            # Default to request path if no resource function provided
            if not resource and request:
                resource = request.path
            
            # Get user ID
            user_id = None
            if current_user and current_user.is_authenticated:
                user_id = current_user.id
            
            # Record start time for performance tracking
            start_time = datetime.now()
            
            try:
                # Call the original function
                result = f(*args, **kwargs)
                
                # Calculate duration
                duration = (datetime.now() - start_time).total_seconds()
                
                # Log successful action
                if audit_logger_instance:
                    audit_logger_instance.log_action(
                        action=action,
                        resource=resource,
                        details={
                            'duration': duration,
                            'args': str(args),
                            'kwargs': str(kwargs)
                        },
                        status='success',
                        user_id=user_id
                    )
                
                return result
            except Exception as e:
                # Calculate duration
                duration = (datetime.now() - start_time).total_seconds()
                
                # Log failed action
                if audit_logger_instance:
                    audit_logger_instance.log_action(
                        action=action,
                        resource=resource,
                        details={
                            'duration': duration,
                            'error': str(e),
                            'args': str(args),
                            'kwargs': str(kwargs)
                        },
                        status='failure',
                        user_id=user_id
                    )
                
                # Re-raise the exception
                raise
        
        return decorated_function
    return decorator

# Convenience function
def log_audit(action, resource=None, details=None, status='success', user_id=None):
    """Log an audit event using the global audit logger"""
    if audit_logger_instance:
        audit_logger_instance.log_action(action, resource, details, status, user_id)
