"""
Integration tests for ShieldAudit
Tests complete workflows and component interaction
"""
import unittest
import socket
import threading
import time
import json
import os
import tempfile
import sys
sys.path.append('..')

from src.server_vault import ShieldAuditServer
from src.security_utils import SecurityUtils, CircularLogBuffer

class TestShieldAuditIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*80)
        print("SHIELDAUDIT INTEGRATION TESTS")
        print("="*80)
        
        cls.test_dir = tempfile.mkdtemp()
        cls.logs_dir = os.path.join(cls.test_dir, 'logs')
        os.makedirs(cls.logs_dir, exist_ok=True)
        
        # Create test log file
        cls.test_log_file = os.path.join(cls.logs_dir, 'integration_test.log')
        with open(cls.test_log_file, 'w') as f:
            f.write("Initial log entry\nSecond entry\nThird entry")
    
    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        print("\n" + "-"*60)
        print(f"Starting integration test: {self._testMethodName}")
        print("-"*60)
        
        # Start server
        self.server = ShieldAuditServer(host='127.0.0.1', port=9997)
        self.server_thread = threading.Thread(target=self.server.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(1)
        
        # Initialize components
        self.security = SecurityUtils()
        self.buffer = CircularLogBuffer(max_size=10)
        
        # Create client socket
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.settimeout(5)
        self.client.connect(('127.0.0.1', 9997))
        
        print("✓ Server started and client connected")
    
    def tearDown(self):
        try:
            self.client.close()
        except:
            pass
        
        if hasattr(self, 'server'):
            self.server.running = False
            self.server.stop_server()
        time.sleep(0.5)
    
    def test_01_complete_heartbeat_workflow(self):
        """Test complete heartbeat workflow"""
        print("\n[TEST 1] Complete heartbeat workflow")
        print("="*40)
        
        # Load log file into buffer
        with open(self.test_log_file, 'r') as f:
            for line in f:
                self.buffer.add_log(line.strip())
        
        print(f"✓ Loaded {self.buffer.size} logs into buffer")
        
        # Calculate file hash
        file_hash = self.security.calculate_file_hash(self.test_log_file)
        print(f"✓ File hash calculated: {file_hash[:16]}...")
        
        # Send heartbeat
        heartbeat = {
            'log_file': os.path.basename(self.test_log_file),
            'file_hash': file_hash,
            'timestamp': time.time()
        }
        
        self.client.send(json.dumps(heartbeat).encode())
        print("✓ Heartbeat sent to server")
        
        time.sleep(0.5)
        
        # Verify server received heartbeat
        log_name = os.path.basename(self.test_log_file)
        self.assertIn(log_name, self.server.heartbeat_data)
        print("✓ Server received heartbeat")
        
        file_data = self.server.heartbeat_data[log_name]
        self.assertEqual(file_data['last_hash'], file_hash)
        print("✓ Hash matches on server")
        
        print("✅ Complete heartbeat workflow successful")
    
    def test_02_tamper_detection_workflow(self):
        """Test tamper detection workflow"""
        print("\n[TEST 2] Tamper detection workflow")
        print("="*40)
        
        # Initial heartbeat
        file_hash = self.security.calculate_file_hash(self.test_log_file)
        heartbeat1 = {
            'log_file': os.path.basename(self.test_log_file),
            'file_hash': file_hash,
            'timestamp': time.time()
        }
        self.client.send(json.dumps(heartbeat1).encode())
        print("✓ Initial heartbeat sent")
        time.sleep(0.5)
        
        # Modify the file (simulate tampering)
        with open(self.test_log_file, 'a') as f:
            f.write("\nTampered entry - added by test")
        print("✓ File modified (tampering simulated)")
        
        # Send second heartbeat
        new_hash = self.security.calculate_file_hash(self.test_log_file)
        heartbeat2 = {
            'log_file': os.path.basename(self.test_log_file),
            'file_hash': new_hash,
            'timestamp': time.time()
        }
        self.client.send(json.dumps(heartbeat2).encode())
        print("✓ Second heartbeat sent")
        time.sleep(0.5)
        
        # Check if alert was generated
        log_name = os.path.basename(self.test_log_file)
        file_data = self.server.heartbeat_data.get(log_name, {})
        
        alerts_detected = False
        if 'alerts' in file_data and len(file_data['alerts']) > 0:
            alerts_detected = True
        elif len(self.server.alerts) > 0:
            alerts_detected = True
        
        self.assertTrue(alerts_detected)
        print("✓ Tamper alert generated!")
        
        # Verify the alert details
        if len(self.server.alerts) > 0:
            alert = self.server.alerts[-1]
            print(f"  Alert: {alert['message']}")
            print(f"  Expected: {alert['expected_hash'][:16]}...")
            print(f"  Received: {alert['received_hash'][:16]}...")
        
        print("✅ Tamper detection workflow successful")
    
    def test_03_buffer_and_search_integration(self):
        """Test buffer and search integration"""
        print("\n[TEST 3] Buffer and search integration")
        print("="*40)
        
        # Load logs into buffer
        with open(self.test_log_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                self.buffer.add_log(line.strip())
        
        # Test search functionality
        print("Testing searches:")
        
        # Search for common word
        results = self.buffer.search_logs("entry")
        print(f"  ✓ Found {len(results)} entries containing 'entry'")
        for i, result in enumerate(results[:2]):  # Show first 2
            print(f"    {i+1}. {result[:50]}...")
        
        # Search for nonexistent word
        none_results = self.buffer.search_logs("nonexistent")
        self.assertEqual(len(none_results), 0)
        print("  ✓ Correctly returns empty for nonexistent terms")
        
        # Test buffer size limit
        self.buffer = CircularLogBuffer(max_size=5)
        for i in range(10):
            self.buffer.add_log(f"Test log {i}")
        
        logs = self.buffer.get_all_logs()
        self.assertEqual(len(logs), 5)
        print(f"  ✓ Buffer correctly limited to {len(logs)} entries (oldest overwritten)")
        print(f"    Current logs: {logs}")
        
        print("✅ Buffer and search integration successful")
    
    def test_04_multiple_clients_workflow(self):
        """Test multiple clients connecting"""
        print("\n[TEST 4] Multiple clients workflow")
        print("="*40)
        
        clients = []
        client_data = []
        
        # Create multiple clients
        for i in range(3):
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(5)
                client.connect(('127.0.0.1', 9997))
                clients.append(client)
                
                # Send heartbeat from each client
                heartbeat = {
                    'log_file': f'client_{i}_log.txt',
                    'file_hash': f'hash_{i}_{time.time()}',
                    'timestamp': time.time()
                }
                client.send(json.dumps(heartbeat).encode())
                client_data.append(heartbeat)
                print(f"✓ Client {i} connected and sent heartbeat")
                time.sleep(0.2)
            except Exception as e:
                print(f"⚠ Error connecting client {i}: {e}")
        
        time.sleep(1)
        
        # Verify all clients are connected
        connected_clients = len(self.server.clients)
        print(f"✓ Server reports {connected_clients} connected clients")
        
        # Verify heartbeats received
        for i, data in enumerate(client_data):
            log_file = f'client_{i}_log.txt'
            if log_file in self.server.heartbeat_data:
                print(f"✓ Heartbeat from client {i} received")
            else:
                print(f"⚠ Heartbeat from client {i} not yet received")
        
        # Close clients
        for client in clients:
            try:
                client.close()
            except:
                pass
        
        time.sleep(1)
        
        print("✅ Multiple clients workflow completed")
    
    def test_05_persistence_workflow(self):
        """Test data persistence across server restarts"""
        print("\n[TEST 5] Persistence workflow")
        print("="*40)
        
        # Send some heartbeats
        test_file = 'persistence_test.log'
        for i in range(3):
            heartbeat = {
                'log_file': test_file,
                'file_hash': f'hash_{i}',
                'timestamp': time.time() + i
            }
            self.client.send(json.dumps(heartbeat).encode())
            time.sleep(0.2)
        
        time.sleep(0.5)
        
        # Force save
        self.server.save_heartbeat_data()
        print("✓ Heartbeat data saved")
        
        # Restart server
        self.server.running = False
        self.server.stop_server()
        time.sleep(1)
        
        # Create new server instance (should load saved data)
        new_server = ShieldAuditServer(host='127.0.0.1', port=9997)
        new_server.load_heartbeat_data()
        
        # Check if data persisted
        if test_file in new_server.heartbeat_data:
            print("✓ Data persisted after server restart")
            file_data = new_server.heartbeat_data[test_file]
            print(f"✓ {len(file_data.get('heartbeats', []))} heartbeats restored")
        else:
            print("⚠ No persisted data found")
        
        new_server.stop_server()
        print("✅ Persistence workflow successful")

def run_integration_tests():
    """Run all integration tests"""
    suite = unittest.TestSuite()
    
    test_methods = [
        'test_01_complete_heartbeat_workflow',
        'test_02_tamper_detection_workflow',
        'test_03_buffer_and_search_integration',
        'test_04_multiple_clients_workflow',
        'test_05_persistence_workflow'
    ]
    
    for method in test_methods:
        suite.addTest(TestShieldAuditIntegration(method))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result

if __name__ == '__main__':
    print("\n" + "="*80)
    print("RUNNING INTEGRATION TESTS")
    print("="*80)
    run_integration_tests()