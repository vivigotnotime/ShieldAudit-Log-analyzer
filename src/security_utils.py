"""
security_utils.py
Purpose: Contains custom data structures and security utilities for the ShieldAudit tool.
Importance: Core component that handles log storage, hashing, and encryption.
"""

import hashlib
import json
import os
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class LogNode:
    """
    Custom Node class for the Circular Buffer (Doubly Linked List implementation)
    Each node represents a single log entry with pointers to next and previous nodes
    """
    def __init__(self, log_entry):
        self.log_entry = log_entry
        self.timestamp = datetime.now()
        self.hash = self.calculate_hash()
        self.next = None
        self.prev = None
    
    def calculate_hash(self):
        """Calculate SHA-256 hash of the log entry"""
        data = f"{self.log_entry}|{self.timestamp}".encode()
        return hashlib.sha256(data).hexdigest()

class CircularLogBuffer:
    """
    Custom Circular Buffer using Doubly Linked List
    Stores only the last N logs (configurable)
    Demonstrates advanced data structure usage
    """
    def __init__(self, max_size=50):
        self.head = None
        self.tail = None
        self.current = None
        self.max_size = max_size
        self.size = 0
    
    def add_log(self, log_entry):
        """Add a new log to the buffer, removing oldest if full"""
        new_node = LogNode(log_entry)
        
        if self.head is None:
            # First log
            self.head = new_node
            self.tail = new_node
            new_node.next = new_node
            new_node.prev = new_node
            self.size = 1
        else:
            # Add to the end
            new_node.prev = self.tail
            new_node.next = self.head
            self.tail.next = new_node
            self.head.prev = new_node
            self.tail = new_node
            
            if self.size < self.max_size:
                self.size += 1
            else:
                # Remove oldest (head)
                self.head = self.head.next
                self.head.prev = self.tail
                self.tail.next = self.head
        
        return new_node.hash
    
    def get_all_logs(self):
        """Return all logs in order"""
        logs = []
        if self.head:
            current = self.head
            logs.append(current.log_entry)
            current = current.next
            while current != self.head:
                logs.append(current.log_entry)
                current = current.next
        return logs
    
    def search_logs(self, keyword):
        """Search logs for a specific keyword"""
        results = []
        if self.head:
            current = self.head
            if keyword.lower() in current.log_entry.lower():
                results.append(current.log_entry)
            current = current.next
            while current != self.head:
                if keyword.lower() in current.log_entry.lower():
                    results.append(current.log_entry)
                current = current.next
        return results

class SecurityUtils:
    """
    Handles encryption, hashing, and security operations
    """
    def __init__(self):
        self.salt = b'shieldaudit_salt_2024'
    
    def generate_key(self, password):
        """Generate encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_data(self, data, password):
        """Encrypt data using password"""
        key = self.generate_key(password)
        f = Fernet(key)
        encrypted = f.encrypt(json.dumps(data).encode())
        return encrypted
    
    def decrypt_data(self, encrypted_data, password):
        """Decrypt data using password"""
        key = self.generate_key(password)
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return json.loads(decrypted.decode())
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return None