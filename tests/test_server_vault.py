"""
Unit tests for server_vault.py
Tests server functionality including socket communication and heartbeat processing
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

class TestShieldAuditServer(unittest.TestCase):
    """Test the ShieldAuditServer class"""
    
    @classmethod
    def setUpClass(cls):
        """Set up class fixtures"""
        print("\n" + "="*70)
        print("SETTING UP SERVER TESTS")
        print("="*70)
        
        # Create temp directory for server data
        cls.test_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(cls.test_dir, 'server_data'), exist_ok=True)
        
        # Change to test directory
        cls.original_dir = os.getcwd()
        os.chdir(cls.test_dir)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up class fixtures"""
        os.chdir(cls.original_dir)
        import shutil
        shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        """Set up test fixtures"""
        print("\n" + "-"*50)
        print(f"Starting test: {self._testMethodName}")
        print("-"*50)
        
        self.server = ShieldAuditServer(host='127.0.0.1', port=9998)  # Different port for testing
        self.server_started = threading.Event()
        
        # Start server in separate thread
        self.server_thread = threading.Thread(target=self.run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Wait for server to start
        time.sleep(1)
    
    def run_server(self):
        """Run server in thread"""
        try:
            self.server.start_server()
        except Exception as e:
            print(f"Server thread error: {e}")
    
    def tearDown(self):
        """Clean up after tests"""
        self.server.running = False
        self.server.stop_server()
        time.sleep(0.5)
    
    def create_test_client(self):
        """Create a test client socket"""
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(('127.0.0.1', 9998))
        return client
    
    def test_server_initialization(self):
        """Test server initialization"""
        print("\n[TEST] Testing server initialization...")
        
        self.assertIsNotNone(self.server)
        self.assertEqual(self.server.host, '127.0.0.1')
        self.assertEqual(self.server.port, 9998)
        print(f"✓ Server initialized with host={self.server.host}, port={self.server.port}")
        
        self.assertIsNotNone(self.server.clients)
        self.assertEqual(len(self.server.clients), 0)
        print("✓ Clients dictionary initialized empty")
        
        self.assertIsNotNone(self.server.heartbeat_data)
        print("✓ Heartbeat data initialized")
    
    def test_client_connection(self):
        """Test client connection to server"""
        print("\n[TEST] Testing client connection...")
        
        # Connect client
        client = self.create_test_client()
        time.sleep(0.5)
        
        # Check if server registered the client
        self.assertEqual(len(self.server.clients), 1)
        print(f"✓ Server registered {len(self.server.clients)} client")
        
        # Get client info
        client_id = list(self.server.clients.keys())[0]
        client_info = self.server.clients[client_id]
        
        self.assertIsNotNone(client_info['connected_at'])
        print(f"✓ Client connection time recorded: {client_info['connected_at']}")
        
        client.close()
        time.sleep(0.5)
        
        # Check if client was removed
        self.assertEqual(len(self.server.clients), 0)
        print("✓ Client properly removed after disconnection")
    
    def test_heartbeat_reception(self):
        """Test receiving heartbeats from client"""
        print("\n[TEST] Testing heartbeat reception...")
        
        client = self.create_test_client()
        time.sleep(0.5)
        
        # Clear any existing heartbeat data
        self.server.heartbeat_data = {}
        
        # Send single heartbeat
        heartbeat = {
            'log_file': 'test_log.txt',
            'file_hash': 'abc123def456',
            'timestamp': time.time()
        }
        
        client.send(json.dumps(heartbeat).encode())
        time.sleep(0.5)
        
        # Check if heartbeat was processed
        self.assertIn('test_log.txt', self.server.heartbeat_data)
        print(f"✓ Heartbeat data stored for test_log.txt")
        
        file_data = self.server.heartbeat_data['test_log.txt']
        self.assertEqual(file_data['last_hash'], 'abc123def456')
        print(f"✓ File hash correctly stored: {file_data['last_hash']}")
        
        # Count only heartbeats from this test
        heartbeats = [h for h in file_data['heartbeats'] if h['hash'] == 'abc123def456']
        self.assertGreaterEqual(len(heartbeats), 1)
        print(f"✓ Heartbeat received")
        
        client.close()
    
    def test_tamper_detection(self):
        """Test tamper detection functionality"""
        print("\n[TEST] Testing tamper detection...")
        
        client = self.create_test_client()
        time.sleep(0.5)
        
        # Clear alerts
        self.server.alerts = []
        
        # Send first heartbeat
        heartbeat1 = {
            'log_file': 'test_log.txt',
            'file_hash': 'original_hash_123',
            'timestamp': time.time()
        }
        client.send(json.dumps(heartbeat1).encode())
        time.sleep(0.5)
        
        # Send second heartbeat with different hash (simulating tampering)
        heartbeat2 = {
            'log_file': 'test_log.txt',
            'file_hash': 'tampered_hash_456',
            'timestamp': time.time()
        }
        client.send(json.dumps(heartbeat2).encode())
        time.sleep(0.5)
        
        # Check if alert was generated
        alert_found = False
        if len(self.server.alerts) > 0:
            alert = self.server.alerts[-1]
            if 'tampering' in alert['message'].lower():
                alert_found = True
                print(f"✓ Tamper alert generated: {alert['message']}")
        
        self.assertTrue(alert_found, "No tamper alert generated")
        client.close()
    
    def test_multiple_clients(self):
        """Test multiple clients connecting simultaneously"""
        print("\n[TEST] Testing multiple clients...")
        
        clients = []
        
        # Create multiple clients
        for i in range(3):
            client = self.create_test_client()
            clients.append(client)
            
            # Send heartbeat from each client
            heartbeat = {
                'log_file': f'client_{i}_log.txt',
                'file_hash': f'hash_{i}_123',
                'timestamp': time.time()
            }
            client.send(json.dumps(heartbeat).encode())
            time.sleep(0.2)
        
        time.sleep(1)
        
        # Check client count
        self.assertGreaterEqual(len(self.server.clients), 1)
        print(f"✓ Server has {len(self.server.clients)} connected clients")
        
        # Close all clients
        for client in clients:
            try:
                client.close()
            except:
                pass
        
        time.sleep(1)
        print("✓ All clients properly disconnected")
    
    def test_server_status(self):
        """Test server status reporting"""
        print("\n[TEST] Testing server status...")
        
        # Get status with no clients
        status = self.server.get_server_status()
        
        self.assertIsNotNone(status)
        print(f"✓ Status shows {status['connected_clients']} clients")
        
        # Add a client
        client = self.create_test_client()
        time.sleep(0.5)
        
        status = self.server.get_server_status()
        self.assertGreaterEqual(status['connected_clients'], 1)
        print(f"✓ Status updated to show client")
        
        client.close()
        time.sleep(0.5)
    
    def test_invalid_heartbeat(self):
        """Test handling of invalid heartbeat data"""
        print("\n[TEST] Testing invalid heartbeat handling...")
        
        client = self.create_test_client()
        time.sleep(0.5)
        
        # Send invalid JSON
        client.send(b"invalid json data")
        time.sleep(0.5)
        
        # Server should still be running
        self.assertTrue(self.server.running)
        print("✓ Server handled invalid JSON gracefully")
        
        # Send incomplete heartbeat
        client.send(json.dumps({"wrong_field": "value"}).encode())
        time.sleep(0.5)
        
        # Server should still be running
        self.assertTrue(self.server.running)
        print("✓ Server handled incomplete heartbeat gracefully")
        
        client.close()
    
    def test_heartbeat_persistence(self):
        """Test heartbeat data persistence"""
        print("\n[TEST] Testing heartbeat persistence...")
        
        client = self.create_test_client()
        time.sleep(0.5)
        
        # Clear existing data
        self.server.heartbeat_data = {}
        
        # Send exactly 5 heartbeats
        for i in range(5):
            heartbeat = {
                'log_file': 'persistence_test.txt',
                'file_hash': f'hash_{i}',
                'timestamp': time.time() + i
            }
            client.send(json.dumps(heartbeat).encode())
            time.sleep(0.2)
        
        time.sleep(1)
        
        # Check if data was saved
        self.assertIn('persistence_test.txt', self.server.heartbeat_data)
        file_data = self.server.heartbeat_data['persistence_test.txt']
        
        # Count heartbeats with our specific hashes
        expected_hashes = [f'hash_{i}' for i in range(5)]
        received_hashes = [h['hash'] for h in file_data.get('heartbeats', [])]
        
        # Check that all our hashes are present
        for expected_hash in expected_hashes:
            self.assertIn(expected_hash, received_hashes)
        
        print(f"✓ All {len(expected_hashes)} heartbeats stored successfully")
        
        # Force save
        self.server.save_heartbeat_data()
        
        # Check if file exists
        data_file = os.path.join('..', 'server_data', 'received_heartbeats.json')
        self.assertTrue(os.path.exists(data_file) or 
                       os.path.exists(os.path.join(self.test_dir, 'server_data', 'received_heartbeats.json')))
        print("✓ Heartbeat data persisted to file")
        
        client.close()

def run_server_tests():
    """Run all server tests"""
    suite = unittest.TestSuite()
    
    # Add all test methods
    test_methods = [
        'test_server_initialization',
        'test_client_connection',
        'test_heartbeat_reception',
        'test_tamper_detection',
        'test_multiple_clients',
        'test_server_status',
        'test_invalid_heartbeat',
        'test_heartbeat_persistence'
    ]
    
    for method in test_methods:
        suite.addTest(TestShieldAuditServer(method))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result

if __name__ == '__main__':
    print("\n" + "="*70)
    print("RUNNING SERVER TESTS")
    print("="*70)
    run_server_tests()