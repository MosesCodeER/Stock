"""
Encryption utilities for Stock Tracker Application
"""

import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('encryption.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('encryption')

class EncryptionManager:
    """Manager for encryption operations"""
    
    def __init__(self, key_file='secret.key'):
        """Initialize encryption manager"""
        self.key_file = key_file
        self.key = self._load_or_generate_key()
        self.cipher_suite = Fernet(self.key)
        
        # Generate RSA key pair for asymmetric encryption
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        logger.info("Encryption manager initialized")
    
    def _load_or_generate_key(self):
        """Load encryption key from file or generate a new one"""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    key = f.read()
                logger.info(f"Loaded encryption key from {self.key_file}")
                return key
            else:
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                logger.info(f"Generated new encryption key and saved to {self.key_file}")
                return key
        except Exception as e:
            logger.error(f"Error loading/generating encryption key: {str(e)}")
            # Fallback to generating a key in memory
            key = Fernet.generate_key()
            logger.info("Generated fallback encryption key in memory")
            return key
    
    def encrypt_data(self, data):
        """Encrypt data using symmetric encryption"""
        try:
            if isinstance(data, str):
                data = data.encode()
            elif isinstance(data, dict) or isinstance(data, list):
                data = json.dumps(data).encode()
            
            encrypted_data = self.cipher_suite.encrypt(data)
            logger.debug("Data encrypted successfully")
            return encrypted_data
        except Exception as e:
            logger.error(f"Error encrypting data: {str(e)}")
            return None
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data using symmetric encryption"""
        try:
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            
            # Try to parse as JSON if possible
            try:
                return json.loads(decrypted_data.decode())
            except:
                return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Error decrypting data: {str(e)}")
            return None
    
    def encrypt_asymmetric(self, data):
        """Encrypt data using asymmetric encryption (RSA)"""
        try:
            if isinstance(data, str):
                data = data.encode()
            elif isinstance(data, dict) or isinstance(data, list):
                data = json.dumps(data).encode()
            
            # RSA can only encrypt small amounts of data, so we use a hybrid approach
            # Generate a random symmetric key
            symmetric_key = os.urandom(32)
            
            # Encrypt the data with the symmetric key
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad the data to a multiple of 16 bytes (AES block size)
            padded_data = data + b'\0' * (16 - len(data) % 16)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Encrypt the symmetric key with the public key
            encrypted_key = self.public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Return the encrypted key, IV, and encrypted data
            result = {
                'encrypted_key': base64.b64encode(encrypted_key).decode(),
                'iv': base64.b64encode(iv).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode()
            }
            
            logger.debug("Data encrypted asymmetrically successfully")
            return result
        except Exception as e:
            logger.error(f"Error encrypting data asymmetrically: {str(e)}")
            return None
    
    def decrypt_asymmetric(self, encrypted_package):
        """Decrypt data using asymmetric encryption (RSA)"""
        try:
            # Extract components
            encrypted_key = base64.b64decode(encrypted_package['encrypted_key'])
            iv = base64.b64decode(encrypted_package['iv'])
            encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
            
            # Decrypt the symmetric key with the private key
            symmetric_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the data with the symmetric key
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            decrypted_data = decrypted_data.rstrip(b'\0')
            
            # Try to parse as JSON if possible
            try:
                return json.loads(decrypted_data.decode())
            except:
                return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Error decrypting data asymmetrically: {str(e)}")
            return None
    
    def derive_key_from_password(self, password, salt=None):
        """Derive a key from a password using PBKDF2"""
        try:
            if salt is None:
                salt = os.urandom(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            
            key = kdf.derive(password.encode())
            
            return {
                'key': base64.b64encode(key).decode(),
                'salt': base64.b64encode(salt).decode()
            }
        except Exception as e:
            logger.error(f"Error deriving key from password: {str(e)}")
            return None
    
    def encrypt_with_password(self, data, password):
        """Encrypt data using a password"""
        try:
            # Derive key from password
            salt = os.urandom(16)
            key_data = self.derive_key_from_password(password, salt)
            key = base64.b64decode(key_data['key'])
            
            # Generate IV
            iv = os.urandom(16)
            
            # Encrypt data
            if isinstance(data, str):
                data = data.encode()
            elif isinstance(data, dict) or isinstance(data, list):
                data = json.dumps(data).encode()
            
            # Pad the data
            padded_data = data + b'\0' * (16 - len(data) % 16)
            
            # Create cipher and encrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Return encrypted package
            result = {
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(iv).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode()
            }
            
            logger.debug("Data encrypted with password successfully")
            return result
        except Exception as e:
            logger.error(f"Error encrypting data with password: {str(e)}")
            return None
    
    def decrypt_with_password(self, encrypted_package, password):
        """Decrypt data using a password"""
        try:
            # Extract components
            salt = base64.b64decode(encrypted_package['salt'])
            iv = base64.b64decode(encrypted_package['iv'])
            encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
            
            # Derive key from password
            key_data = self.derive_key_from_password(password, salt)
            key = base64.b64decode(key_data['key'])
            
            # Decrypt data
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            decrypted_data = decrypted_data.rstrip(b'\0')
            
            # Try to parse as JSON if possible
            try:
                return json.loads(decrypted_data.decode())
            except:
                return decrypted_data.decode()
        except Exception as e:
            logger.error(f"Error decrypting data with password: {str(e)}")
            return None
    
    def encrypt_api_response(self, data):
        """Encrypt API response data"""
        try:
            # For API responses, we use symmetric encryption for performance
            if isinstance(data, dict) or isinstance(data, list):
                # Identify sensitive fields and encrypt only those
                if isinstance(data, dict):
                    result = {}
                    for key, value in data.items():
                        if self._is_sensitive_field(key):
                            # Encrypt sensitive fields
                            encrypted_value = self.encrypt_data(value)
                            result[key] = {
                                'encrypted': True,
                                'data': base64.b64encode(encrypted_value).decode()
                            }
                        else:
                            # Recursively process nested objects
                            if isinstance(value, dict) or isinstance(value, list):
                                result[key] = self.encrypt_api_response(value)
                            else:
                                result[key] = value
                    return result
                else:  # List
                    return [self.encrypt_api_response(item) for item in data]
            else:
                # For non-dict/list data, return as is
                return data
        except Exception as e:
            logger.error(f"Error encrypting API response: {str(e)}")
            return data
    
    def decrypt_api_response(self, data):
        """Decrypt API response data"""
        try:
            # Process dictionaries and lists recursively
            if isinstance(data, dict):
                # Check if this is an encrypted field
                if 'encrypted' in data and data['encrypted'] and 'data' in data:
                    encrypted_data = base64.b64decode(data['data'])
                    return self.decrypt_data(encrypted_data)
                
                # Otherwise process each field
                result = {}
                for key, value in data.items():
                    if isinstance(value, dict) or isinstance(value, list):
                        result[key] = self.decrypt_api_response(value)
                    else:
                        result[key] = value
                return result
            elif isinstance(data, list):
                return [self.decrypt_api_response(item) for item in data]
            else:
                return data
        except Exception as e:
            logger.error(f"Error decrypting API response: {str(e)}")
            return data
    
    def _is_sensitive_field(self, field_name):
        """Determine if a field is sensitive and should be encrypted"""
        sensitive_fields = [
            'password', 'token', 'key', 'secret', 'credential', 'auth',
            'ssn', 'social', 'credit', 'card', 'cvv', 'pin', 'account',
            'email', 'phone', 'address', 'zip', 'postal', 'license',
            'passport', 'dob', 'birth', 'gender', 'race', 'ethnicity',
            'health', 'medical', 'income', 'salary', 'tax'
        ]
        
        field_lower = field_name.lower()
        return any(sensitive in field_lower for sensitive in sensitive_fields)

# Create a global instance for use throughout the application
encryption_manager = EncryptionManager()

# Convenience functions
def encrypt_data(data):
    """Encrypt data using the global encryption manager"""
    return encryption_manager.encrypt_data(data)

def decrypt_data(encrypted_data):
    """Decrypt data using the global encryption manager"""
    return encryption_manager.decrypt_data(encrypted_data)

def encrypt_api_response(data):
    """Encrypt API response using the global encryption manager"""
    return encryption_manager.encrypt_api_response(data)

def decrypt_api_response(data):
    """Decrypt API response using the global encryption manager"""
    return encryption_manager.decrypt_api_response(data)

def encrypt_with_password(data, password):
    """Encrypt data with a password using the global encryption manager"""
    return encryption_manager.encrypt_with_password(data, password)

def decrypt_with_password(encrypted_package, password):
    """Decrypt data with a password using the global encryption manager"""
    return encryption_manager.decrypt_with_password(encrypted_package, password)
