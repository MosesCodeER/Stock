"""
Database encryption for Stock Tracker Application
"""

from sqlalchemy import event, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from encryption import encrypt_data, decrypt_data
import logging
import json
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('db_encryption.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('db_encryption')

# Define sensitive fields that should be encrypted in the database
SENSITIVE_FIELDS = {
    'user': ['password_hash', 'email'],
    'login_log': ['ip_address', 'user_agent'],
    'audit_log': ['ip_address', 'details']
}

class EncryptedEngine:
    """Wrapper for SQLAlchemy engine with encryption capabilities"""
    
    def __init__(self, db_uri):
        """Initialize the encrypted engine"""
        self.engine = create_engine(db_uri)
        self.setup_encryption_hooks()
        logger.info("Encrypted database engine initialized")
    
    def setup_encryption_hooks(self):
        """Set up SQLAlchemy event hooks for encryption/decryption"""
        
        @event.listens_for(self.engine, "before_cursor_execute")
        def encrypt_bind_params(conn, cursor, statement, parameters, context, executemany):
            """Encrypt sensitive parameters before they are sent to the database"""
            if executemany:
                # Handle batch operations
                new_parameters = []
                for params in parameters:
                    new_parameters.append(self._encrypt_parameters(statement, params))
                return statement, new_parameters
            else:
                # Handle single operations
                return statement, self._encrypt_parameters(statement, parameters)
        
        @event.listens_for(self.engine, "result")
        def decrypt_results(conn, result):
            """Decrypt sensitive data in query results"""
            # This is a simplified approach - in a real application, you would need
            # more sophisticated logic to identify which columns need decryption
            for row in result:
                for i, value in enumerate(row):
                    if isinstance(value, str) and value.startswith('ENC:'):
                        # Decrypt the value
                        encrypted_data = base64.b64decode(value[4:])
                        decrypted_value = decrypt_data(encrypted_data)
                        row._data[i] = decrypted_value
    
    def _encrypt_parameters(self, statement, parameters):
        """Encrypt sensitive parameters based on the SQL statement"""
        if not parameters:
            return parameters
        
        # Determine which table is being affected
        table_name = self._extract_table_name(statement)
        if not table_name or table_name not in SENSITIVE_FIELDS:
            return parameters
        
        # Get sensitive fields for this table
        sensitive_fields = SENSITIVE_FIELDS[table_name]
        
        # Create new parameters with encrypted values
        if isinstance(parameters, dict):
            new_params = {}
            for key, value in parameters.items():
                if key in sensitive_fields and value is not None:
                    # Encrypt the value
                    encrypted_value = encrypt_data(value)
                    new_params[key] = f"ENC:{base64.b64encode(encrypted_value).decode()}"
                else:
                    new_params[key] = value
            return new_params
        else:
            # For non-dict parameters, return as is
            return parameters
    
    def _extract_table_name(self, statement):
        """Extract table name from SQL statement"""
        # This is a simplified approach - in a real application, you would need
        # more sophisticated SQL parsing
        statement = statement.lower()
        
        # Check for INSERT
        if 'insert into' in statement:
            parts = statement.split('insert into')[1].strip().split()
            return parts[0].strip('`"[]')
        
        # Check for UPDATE
        elif 'update' in statement:
            parts = statement.split('update')[1].strip().split()
            return parts[0].strip('`"[]')
        
        # Check for SELECT
        elif 'from' in statement:
            parts = statement.split('from')[1].strip().split()
            return parts[0].strip('`"[]')
        
        return None
    
    def get_session(self):
        """Get a database session with encryption support"""
        Session = sessionmaker(bind=self.engine)
        return Session()

# Create a function to initialize the encrypted database
def init_encrypted_db(app):
    """Initialize the encrypted database"""
    db_uri = app.config['SQLALCHEMY_DATABASE_URI']
    encrypted_engine = EncryptedEngine(db_uri)
    
    # Store the encrypted engine in the app config
    app.config['ENCRYPTED_ENGINE'] = encrypted_engine
    
    logger.info("Encrypted database initialized")
    return encrypted_engine

# Create a function to get an encrypted session
def get_encrypted_session(app):
    """Get a database session with encryption support"""
    if 'ENCRYPTED_ENGINE' not in app.config:
        init_encrypted_db(app)
    
    return app.config['ENCRYPTED_ENGINE'].get_session()
