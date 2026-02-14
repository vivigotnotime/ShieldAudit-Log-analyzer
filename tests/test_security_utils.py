"""
Unit tests for security_utils.py
Tests custom data structures and cryptographic functions
"""
import unittest
import tempfile
import os
import json
import time
from datetime import datetime
import sys
sys.path.append('..')

from src.security_utils import LogNode, CircularLogBuffer, SecurityUtils

class TestLogNode(unittest.TestCase):
    """Test the LogNode class"""
    
    def setUp(self):
        """Set up test fixtures"""
        print("\n" + "="*70)
        print("Setting up LogNode test")
        print("="*70)
        self.test_log = "Test log entry"
        self.node = LogNode(self.test_log)
    
    def test_initialization(self):
        """Test LogNode initialization"""
        print("\n[TEST] Testing LogNode initialization...")
        
        # Test log entry
        self.assertEqual(self.node.log_entry, self.test_log)
        print(f"✓ Log entry correctly set: '{self.node.log_entry}'")
        
        # Test timestamp
        self.assertIsInstance(self.node.timestamp, datetime)
        print(f"✓ Timestamp correctly set: {self.node.timestamp}")
        
        # Test hash
        self.assertIsNotNone(self.node.hash)
        self.assertEqual(len(self.node.hash), 64)  # SHA-256 produces 64 hex chars
        print(f"✓ Hash correctly generated: {self.node.hash[:16]}...")
        
        # Test pointers
        self.assertIsNone(self.node.next)
        self.assertIsNone(self.node.prev)
        print("✓ Next and prev pointers correctly initialized to None")
    
    def test_hash_calculation(self):
        """Test hash calculation consistency"""
        print("\n[TEST] Testing hash calculation consistency...")
        
        # Get initial hash
        hash1 = self.node.hash
        
        # Create a new node to force different timestamp
        time.sleep(0.1)  # Small delay
        node2 = LogNode(self.test_log)
        hash2 = node2.hash
        
        # Hash should be different due to different timestamp
        self.assertNotEqual(hash1, hash2)
        print("✓ Hash changes with timestamp as expected")
    
    def test_hash_uniqueness(self):
        """Test that different logs produce different hashes"""
        print("\n[TEST] Testing hash uniqueness...")
        
        node1 = LogNode("Log entry 1")
        node2 = LogNode("Log entry 2")
        
        self.assertNotEqual(node1.hash, node2.hash)
        print("✓ Different log entries produce different hashes")

class TestCircularLogBuffer(unittest.TestCase):
    """Test the CircularLogBuffer class"""
    
    def setUp(self):
        """Set up test fixtures"""
        print("\n" + "="*70)
        print("Setting up CircularLogBuffer test")
        print("="*70)
        self.buffer = CircularLogBuffer(max_size=5)
        self.test_logs = [
            "Log entry 1",
            "Log entry 2", 
            "Log entry 3",
            "Log entry 4",
            "Log entry 5",
            "Log entry 6",  # This should cause overwrite
            "Log entry 7"
        ]
    
    def test_initialization(self):
        """Test buffer initialization"""
        print("\n[TEST] Testing buffer initialization...")
        
        self.assertIsNone(self.buffer.head)
        self.assertIsNone(self.buffer.tail)
        self.assertEqual(self.buffer.max_size, 5)
        self.assertEqual(self.buffer.size, 0)
        print("✓ Buffer correctly initialized")
    
    def test_add_log_until_full(self):
        """Test adding logs until buffer is full"""
        print("\n[TEST] Testing adding logs until full...")
        
        # Add first 5 logs
        for i in range(5):
            hash_val = self.buffer.add_log(self.test_logs[i])
            print(f"  Added log {i+1}: hash={hash_val[:16]}...")
        
        self.assertEqual(self.buffer.size, 5)
        self.assertIsNotNone(self.buffer.head)
        self.assertIsNotNone(self.buffer.tail)
        print(f"✓ Buffer size correctly reported as {self.buffer.size}")
        
        # Verify all logs are retrievable
        all_logs = self.buffer.get_all_logs()
        self.assertEqual(len(all_logs), 5)
        print(f"✓ Retrieved {len(all_logs)} logs correctly")
    
    def test_circular_behavior(self):
        """Test circular buffer overwriting behavior"""
        print("\n[TEST] Testing circular buffer overwrite behavior...")
        
        # Add 7 logs to a buffer of size 5
        for i, log in enumerate(self.test_logs):
            self.buffer.add_log(log)
            print(f"  Added log {i+1}: {log[:15]}...")
        
        # Size should still be 5
        self.assertEqual(self.buffer.size, 5)
        print(f"✓ Buffer size maintained at {self.buffer.size}")
        
        # Get all logs - should be the last 5
        all_logs = self.buffer.get_all_logs()
        expected_logs = self.test_logs[-5:]  # Last 5 logs
        
        self.assertEqual(len(all_logs), 5)
        self.assertEqual(all_logs, expected_logs)
        print("✓ Buffer correctly overwrote oldest entries")
        print(f"  Current logs: {all_logs}")
    
    def test_linked_list_structure(self):
        """Test the doubly linked list structure"""
        print("\n[TEST] Testing doubly linked list structure...")
        
        # Add some logs
        for log in self.test_logs[:3]:
            self.buffer.add_log(log)
        
        # Test forward traversal
        print("  Testing forward traversal...")
        current = self.buffer.head
        logs_forward = []
        for _ in range(self.buffer.size):
            logs_forward.append(current.log_entry)
            current = current.next
        
        # Test backward traversal
        print("  Testing backward traversal...")
        current = self.buffer.tail
        logs_backward = []
        for _ in range(self.buffer.size):
            logs_backward.append(current.log_entry)
            current = current.prev
        
        logs_backward.reverse()
        
        self.assertEqual(logs_forward, logs_backward)
        print("✓ Forward and backward traversal match")
        print(f"  Logs: {logs_forward}")
    
    def test_search_functionality(self):
        """Test log searching"""
        print("\n[TEST] Testing search functionality...")
        
        # Add logs with specific keywords
        self.buffer.add_log("ERROR: Database connection failed")
        self.buffer.add_log("INFO: User logged in")
        self.buffer.add_log("WARNING: High memory usage")
        self.buffer.add_log("ERROR: Network timeout")
        self.buffer.add_log("INFO: Backup completed")
        
        # Search for ERROR
        error_results = self.buffer.search_logs("ERROR")
        self.assertEqual(len(error_results), 2)
        print(f"✓ Found {len(error_results)} logs containing 'ERROR'")
        
        # Search for INFO
        info_results = self.buffer.search_logs("INFO")
        self.assertEqual(len(info_results), 2)
        print(f"✓ Found {len(info_results)} logs containing 'INFO'")
        
        # Search for nonexistent term
        none_results = self.buffer.search_logs("NONEXISTENT")
        self.assertEqual(len(none_results), 0)
        print("✓ Correctly returns empty list for nonexistent terms")

class TestSecurityUtils(unittest.TestCase):
    """Test the SecurityUtils class"""
    
    def setUp(self):
        """Set up test fixtures"""
        print("\n" + "="*70)
        print("Setting up SecurityUtils test")
        print("="*70)
        self.security = SecurityUtils()
        self.test_password = "test_password_123"
        self.test_data = {
            "user": "admin",
            "role": "administrator",
            "timestamp": str(datetime.now())
        }
        
        # Create temporary test file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.temp_file.write("This is a test log file\nLine 2\nLine 3")
        self.temp_file.close()
    
    def tearDown(self):
        """Clean up after tests"""
        try:
            os.unlink(self.temp_file.name)
        except:
            pass
    
    def test_key_generation(self):
        """Test encryption key generation"""
        print("\n[TEST] Testing key generation...")
        
        key1 = self.security.generate_key(self.test_password)
        key2 = self.security.generate_key(self.test_password)
        
        self.assertEqual(key1, key2)  # Same password should generate same key
        print("✓ Same password generates same key")
        
        key3 = self.security.generate_key("different_password")
        self.assertNotEqual(key1, key3)
        print("✓ Different passwords generate different keys")
    
    def test_encryption_decryption(self):
        """Test encryption and decryption"""
        print("\n[TEST] Testing encryption/decryption...")
        
        # Encrypt
        encrypted = self.security.encrypt_data(self.test_data, self.test_password)
        self.assertIsInstance(encrypted, bytes)
        print(f"✓ Data encrypted successfully: {len(encrypted)} bytes")
        
        # Decrypt
        decrypted = self.security.decrypt_data(encrypted, self.test_password)
        self.assertEqual(decrypted, self.test_data)
        print("✓ Data decrypted successfully and matches original")
        
        # Test with wrong password
        with self.assertRaises(Exception):
            self.security.decrypt_data(encrypted, "wrong_password")
        print("✓ Wrong password correctly causes decryption error")
    
    def test_file_hash_calculation(self):
        """Test file hash calculation"""
        print("\n[TEST] Testing file hash calculation...")
        
        # Calculate hash
        file_hash = self.security.calculate_file_hash(self.temp_file.name)
        
        self.assertIsNotNone(file_hash)
        self.assertEqual(len(file_hash), 64)
        print(f"✓ File hash calculated: {file_hash[:16]}...")
        
        # Modify file and recalculate
        with open(self.temp_file.name, 'a') as f:
            f.write("\nNew line added")
        
        new_hash = self.security.calculate_file_hash(self.temp_file.name)
        self.assertNotEqual(file_hash, new_hash)
        print("✓ Hash changes when file is modified")
        
        # Test nonexistent file
        none_hash = self.security.calculate_file_hash("nonexistent_file.txt")
        self.assertIsNone(none_hash)
        print("✓ Nonexistent file returns None")
    
    def test_hash_consistency(self):
        """Test hash consistency for same file"""
        print("\n[TEST] Testing hash consistency...")
        
        hash1 = self.security.calculate_file_hash(self.temp_file.name)
        hash2 = self.security.calculate_file_hash(self.temp_file.name)
        
        self.assertEqual(hash1, hash2)
        print("✓ Same file produces same hash consistently")

def run_security_tests():
    """Run all security utility tests"""
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(TestLogNode('test_initialization'))
    suite.addTest(TestLogNode('test_hash_calculation'))
    suite.addTest(TestLogNode('test_hash_uniqueness'))
    
    suite.addTest(TestCircularLogBuffer('test_initialization'))
    suite.addTest(TestCircularLogBuffer('test_add_log_until_full'))
    suite.addTest(TestCircularLogBuffer('test_circular_behavior'))
    suite.addTest(TestCircularLogBuffer('test_linked_list_structure'))
    suite.addTest(TestCircularLogBuffer('test_search_functionality'))
    
    suite.addTest(TestSecurityUtils('test_key_generation'))
    suite.addTest(TestSecurityUtils('test_encryption_decryption'))
    suite.addTest(TestSecurityUtils('test_file_hash_calculation'))
    suite.addTest(TestSecurityUtils('test_hash_consistency'))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result

if __name__ == '__main__':
    print("\n" + "="*70)
    print("RUNNING SECURITY UTILITIES TESTS")
    print("="*70)
    run_security_tests()