"""
server_vault.py
Purpose: Central server that receives and validates integrity heartbeats
Importance: Core of the distributed architecture - monitors client integrity in real-time
"""

import socket
import threading
import json
import hashlib
from datetime import datetime
import os
import sys
import time

class ShieldAuditServer:
    """
    True server implementation using TCP sockets
    Listens for client connections and validates log integrity
    """
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.heartbeat_data = {}
        self.running = False
        self.alerts = []
        
        # Create server data directory if it doesn't exist
        os.makedirs('../server_data', exist_ok=True)
        self.load_heartbeat_data()
    
    def load_heartbeat_data(self):
        """Load existing heartbeat data from file"""
        try:
            with open('../server_data/received_heartbeats.json', 'r') as f:
                self.heartbeat_data = json.load(f)
        except FileNotFoundError:
            self.heartbeat_data = {}
        except json.JSONDecodeError:
            self.heartbeat_data = {}
    
    def save_heartbeat_data(self):
        """Save heartbeat data to file"""
        try:
            with open('../server_data/received_heartbeats.json', 'w') as f:
                json.dump(self.heartbeat_data, f, indent=2)
        except Exception as e:
            print(f"Error saving heartbeat data: {e}")
    
    def start_server(self):
        """Start the server socket and listen for connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f"🔒 ShieldAudit Vault Server started on {self.host}:{self.port}")
            print("Waiting for client connections...")
            print("Press Ctrl+C to stop the server")
            
            # Start accepting clients in a separate thread
            accept_thread = threading.Thread(target=self.accept_clients)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Keep server running
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nShutting down server...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop_server()
    
    def accept_clients(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                print(f"✅ New client connected from {address[0]}:{address[1]}")
            except Exception as e:
                if self.running:
                    print(f"Error accepting client: {e}")
                break
    
    def handle_client(self, client_socket, address):
        """Handle individual client connections"""
        client_id = f"{address[0]}:{address[1]}"
        self.clients[client_id] = {
            'socket': client_socket,
            'address': address,
            'connected_at': datetime.now().isoformat(),
            'last_heartbeat': None
        }
        
        try:
            while self.running:
                # Receive heartbeat from client
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                # Parse heartbeat data
                try:
                    heartbeat = json.loads(data)
                    self.process_heartbeat(client_id, heartbeat)
                except json.JSONDecodeError:
                    print(f"Invalid heartbeat data from {client_id}")
                    continue
                
        except (ConnectionResetError, BrokenPipeError):
            print(f"Client {client_id} disconnected unexpectedly")
        except Exception as e:
            print(f"Client {client_id} error: {e}")
        finally:
            self.remove_client(client_id)
            try:
                client_socket.close()
            except:
                pass
    
    def process_heartbeat(self, client_id, heartbeat):
        """Process received heartbeat data"""
        log_file = heartbeat.get('log_file', 'unknown')
        file_hash = heartbeat.get('file_hash')
        timestamp = heartbeat.get('timestamp', datetime.now().isoformat())
        
        # Update client's last heartbeat
        if client_id in self.clients:
            self.clients[client_id]['last_heartbeat'] = timestamp
        
        # Check if this log file is being monitored
        if log_file not in self.heartbeat_data:
            self.heartbeat_data[log_file] = {
                'initial_hash': file_hash,
                'heartbeats': [],
                'alerts': []
            }
        
        # Verify integrity
        previous_hash = self.heartbeat_data[log_file].get('last_hash')
        if previous_hash and previous_hash != file_hash:
            # Tamper detected!
            alert = {
                'client_id': client_id,
                'log_file': log_file,
                'expected_hash': previous_hash,
                'received_hash': file_hash,
                'timestamp': datetime.now().isoformat(),
                'message': '⚠️ SECURITY ALERT: Log file tampering detected!'
            }
            self.alerts.append(alert)
            self.heartbeat_data[log_file]['alerts'].append(alert)
            
            print(f"\n🔴 {alert['message']}")
            print(f"File: {log_file}")
            print(f"Expected: {previous_hash[:16]}...")
            print(f"Received: {file_hash[:16]}...\n")
        
        # Store heartbeat
        self.heartbeat_data[log_file]['last_hash'] = file_hash
        self.heartbeat_data[log_file]['heartbeats'].append({
            'timestamp': timestamp,
            'hash': file_hash,
            'client': client_id
        })
        
        # Keep only last 100 heartbeats per file
        if len(self.heartbeat_data[log_file]['heartbeats']) > 100:
            self.heartbeat_data[log_file]['heartbeats'] = self.heartbeat_data[log_file]['heartbeats'][-100:]
        
        # Save data periodically
        if len(self.heartbeat_data[log_file]['heartbeats']) % 10 == 0:
            self.save_heartbeat_data()
        
        # Send acknowledgment to client
        try:
            response = {
                'status': 'received',
                'alert_detected': previous_hash and previous_hash != file_hash
            }
            self.clients[client_id]['socket'].send(json.dumps(response).encode())
        except:
            pass
    
    def remove_client(self, client_id):
        """Remove disconnected client"""
        if client_id in self.clients:
            del self.clients[client_id]
            print(f"❌ Client disconnected: {client_id}")
    
    def stop_server(self):
        """Stop the server gracefully"""
        self.running = False
        print("Stopping server...")
        
        # Close all client connections
        for client_id, client_data in list(self.clients.items()):
            try:
                client_data['socket'].close()
            except:
                pass
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Final save
        self.save_heartbeat_data()
        print("Server stopped")
    
    def get_server_status(self):
        """Get current server status"""
        return {
            'running': self.running,
            'connected_clients': len(self.clients),
            'clients': list(self.clients.keys()),
            'alerts': self.alerts[-10:],  # Last 10 alerts
            'monitored_files': list(self.heartbeat_data.keys())
        }

def run_server():
    """Function to run the server"""
    server = ShieldAuditServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop_server()

if __name__ == "__main__":
    run_server()