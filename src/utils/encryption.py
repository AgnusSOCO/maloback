"""
Encryption utilities for secure bank credential storage
Uses AES-256 encryption with random IV for each encryption operation
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class CredentialEncryption:
    """Handles encryption and decryption of sensitive bank credentials"""
    
    def __init__(self, master_key=None):
        """
        Initialize encryption with master key
        In production, this should come from environment variables or key management service
        """
        if master_key is None:
            # Use environment variable or generate a key (for demo purposes)
            master_key = os.environ.get('ENCRYPTION_MASTER_KEY', 'demo-key-change-in-production')
        
        self.master_key = master_key.encode('utf-8')
        self.backend = default_backend()
    
    def _derive_key(self, salt):
        """Derive encryption key from master key using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self.master_key)
    
    def encrypt_credential(self, plaintext):
        """
        Encrypt a credential string
        Returns: (encrypted_data, iv, salt) as bytes
        """
        if not plaintext:
            return None, None, None
        
        # Generate random salt and IV
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        # Derive key from master key and salt
        key = self._derive_key(salt)
        
        # Create cipher and encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Pad plaintext to multiple of 16 bytes (AES block size)
        plaintext_bytes = plaintext.encode('utf-8')
        padding_length = 16 - (len(plaintext_bytes) % 16)
        padded_plaintext = plaintext_bytes + bytes([padding_length] * padding_length)
        
        # Encrypt
        encrypted_data = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return encrypted_data, iv, salt
    
    def decrypt_credential(self, encrypted_data, iv, salt):
        """
        Decrypt a credential
        Returns: plaintext string
        """
        if not encrypted_data or not iv or not salt:
            return None
        
        # Derive key from master key and salt
        key = self._derive_key(salt)
        
        # Create cipher and decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext_bytes = padded_plaintext[:-padding_length]
        
        return plaintext_bytes.decode('utf-8')
    
    def encrypt_credentials_for_storage(self, username, password):
        """
        Encrypt both username and password for database storage
        Returns: dict with encrypted data ready for database
        """
        username_enc, username_iv, username_salt = self.encrypt_credential(username)
        password_enc, password_iv, password_salt = self.encrypt_credential(password)
        
        # Combine IV and salt for storage (we'll use the same approach for both)
        username_combined = username_iv + username_salt if username_iv and username_salt else None
        password_combined = password_iv + password_salt if password_iv and password_salt else None
        
        return {
            'username_enc': username_enc,
            'password_enc': password_enc,
            'iv': username_combined,  # Store combined IV+salt
            'kek_version': 1
        }
    
    def decrypt_credentials_from_storage(self, username_enc, password_enc, iv_combined):
        """
        Decrypt credentials from database storage format
        Returns: (username, password) tuple
        """
        if not username_enc or not password_enc or not iv_combined:
            return None, None
        
        # Split combined IV+salt (first 16 bytes = IV, next 16 bytes = salt)
        iv = iv_combined[:16]
        salt = iv_combined[16:32]
        
        username = self.decrypt_credential(username_enc, iv, salt)
        password = self.decrypt_credential(password_enc, iv, salt)
        
        return username, password

# Global encryption instance
encryption = CredentialEncryption()

def encrypt_bank_credentials(username, password):
    """Convenience function to encrypt bank credentials"""
    return encryption.encrypt_credentials_for_storage(username, password)

def decrypt_bank_credentials(username_enc, password_enc, iv_combined):
    """Convenience function to decrypt bank credentials"""
    return encryption.decrypt_credentials_from_storage(username_enc, password_enc, iv_combined)

