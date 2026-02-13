"""
main_gui.py
Purpose: Main client application with Tkinter GUI
Importance: User interface for log viewing, integrity monitoring, and server communication
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import socket
import json
import time
import os
import sys
from datetime import datetime
import hashlib

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.security_utils import CircularLogBuffer, SecurityUtils

class LoginWindow:
    """Login window for user authentication"""
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("ShieldAudit - Login")
        self.window.geometry("400x500")
        self.window.configure(bg='#abb1cf')
        
        # Center the window
        self.window.eval('tk::PlaceWindow . center')
        
        # User credentials (for demo purposes)
        self.users = {
            'admin': {
                'password': 'admin123',
                'role': 'Administrator',
                'purpose': 'Full access to all logs and server controls'
            },
            'auditor': {
                'password': 'audit123',
                'role': 'Security Auditor',
                'purpose': 'View logs and integrity reports only'
            },
            'analyst': {
                'password': 'analyze123',
                'role': 'Log Analyst',
                'purpose': 'Search and filter logs, view alerts'
            }
        }
        
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title_label = tk.Label(
            self.window,
            text="🔒 ShieldAudit",
            font=("Arial", 24, "bold"),
            bg='#abb1cf',
            fg='#2d2d2d'
        )
        title_label.pack(pady=30)
        
        subtitle_label = tk.Label(
            self.window,
            text="Secure Distributed Log Integrity Guard",
            font=("Arial", 10),
            bg='#abb1cf',
            fg='#2d2d2d'
        )
        subtitle_label.pack(pady=10)
        
        # Login frame
        login_frame = tk.Frame(self.window, bg='#92a8d1', padx=20, pady=20)
        login_frame.pack(pady=20)
        
        # Username
        tk.Label(
            login_frame,
            text="Username:",
            font=("Arial", 11),
            bg='#92a8d1',
            fg='#2d2d2d'
        ).grid(row=0, column=0, pady=5, sticky='w')
        
        self.username_var = tk.StringVar(value="admin")
        username_entry = tk.Entry(
            login_frame,
            textvariable=self.username_var,
            font=("Arial", 11),
            width=20
        )
        username_entry.grid(row=0, column=1, pady=5, padx=10)
        
        # Password
        tk.Label(
            login_frame,
            text="Password:",
            font=("Arial", 11),
            bg='#92a8d1',
            fg='#2d2d2d'
        ).grid(row=1, column=0, pady=5, sticky='w')
        
        self.password_var = tk.StringVar(value="admin123")
        password_entry = tk.Entry(
            login_frame,
            textvariable=self.password_var,
            font=("Arial", 11),
            width=20,
            show="*"
        )
        password_entry.grid(row=1, column=1, pady=5, padx=10)
        
        # Login button
        login_btn = tk.Button(
            login_frame,
            text="Login",
            font=("Arial", 11, "bold"),
            bg='#e17369',
            fg='#2d2d2d',
            padx=20,
            pady=5,
            command=self.login
        )
        login_btn.grid(row=2, column=0, columnspan=2, pady=20)
        
        # User info section
        info_frame = tk.Frame(self.window, bg='#abb1cf')
        info_frame.pack(pady=20, fill='both', expand=True)
        
        tk.Label(
            info_frame,
            text="Demo Credentials:",
            font=("Arial", 11, "bold"),
            bg='#abb1cf',
            fg='#2d2d2d'
        ).pack()
        
        # Display user credentials
        for username, data in self.users.items():
            user_text = f"• {username}: {data['password']} - {data['role']}"
            tk.Label(
                info_frame,
                text=user_text,
                font=("Arial", 9),
                bg='#abb1cf',
                fg='#2d2d2d',
                anchor='w'
            ).pack(pady=2, padx=20, fill='x')
    
    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        
        if username in self.users and self.users[username]['password'] == password:
            self.window.destroy()
            # Open main application
            app = ShieldAuditGUI(self.users[username])
            app.run()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
    
    def run(self):
        self.window.mainloop()

class ShieldAuditGUI:
    """Main GUI Application"""
    def __init__(self, user_info):
        self.user = user_info
        self.root = tk.Tk()
        self.root.title(f"ShieldAudit - Logged in as {user_info['role']}")
        self.root.geometry("1400x800")
        self.root.configure(bg='#abb1cf')
        
        # Initialize components
        self.log_buffer = CircularLogBuffer(max_size=100)
        self.security_utils = SecurityUtils()
        self.current_log_file = None
        self.server_process = None
        self.monitoring = False
        self.last_hash = None
        self.client_socket = None
        self.server_ready = False
        self.heartbeat_thread_running = False
        
        # Color scheme
        self.colors = {
            'bg1': '#e17369',
            'bg2': '#e95f69',
            'bg3': '#f3b2ad',
            'bg4': '#abb1cf',
            'bg5': '#92a8d1',
            'text': '#2d2d2d'
        }
        
        self.create_widgets()
        self.setup_log_files()
        
        # Set up protocol for window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg4'])
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left panel - Controls
        left_panel = tk.Frame(main_frame, bg=self.colors['bg5'], width=300)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Right panel - Log display
        right_panel = tk.Frame(main_frame, bg=self.colors['bg4'])
        right_panel.pack(side='right', fill='both', expand=True)
        
        # ========== LEFT PANEL WIDGETS ==========
        
        # User info
        user_frame = tk.Frame(left_panel, bg=self.colors['bg5'])
        user_frame.pack(fill='x', pady=10, padx=10)
        
        tk.Label(
            user_frame,
            text=f"👤 {self.user['role']}",
            font=("Arial", 12, "bold"),
            bg=self.colors['bg5'],
            fg=self.colors['text']
        ).pack()
        
        tk.Label(
            user_frame,
            text=f"Purpose: {self.user['purpose']}",
            font=("Arial", 9),
            bg=self.colors['bg5'],
            fg=self.colors['text'],
            wraplength=250
        ).pack(pady=5)
        
        # Server Control Section
        server_frame = tk.LabelFrame(
            left_panel,
            text="🖥️ Server Control",
            bg=self.colors['bg5'],
            fg=self.colors['text'],
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        server_frame.pack(fill='x', pady=10, padx=10)
        
        self.server_status_label = tk.Label(
            server_frame,
            text="Server: Stopped",
            font=("Arial", 10),
            bg=self.colors['bg5'],
            fg=self.colors['text']
        )
        self.server_status_label.pack(pady=5)
        
        self.start_server_btn = tk.Button(
            server_frame,
            text="🚀 Start Server",
            font=("Arial", 10, "bold"),
            bg=self.colors['bg1'],
            fg=self.colors['text'],
            command=self.start_server
        )
        self.start_server_btn.pack(fill='x', pady=5)
        
        self.connect_btn = tk.Button(
            server_frame,
            text="🔌 Connect to Server",
            font=("Arial", 10, "bold"),
            bg=self.colors['bg2'],
            fg=self.colors['text'],
            command=self.connect_to_server,
            state='disabled'
        )
        self.connect_btn.pack(fill='x', pady=5)
        
        # Server connection status
        self.connection_status_label = tk.Label(
            server_frame,
            text="Not Connected",
            font=("Arial", 9),
            bg=self.colors['bg5'],
            fg='red'
        )
        self.connection_status_label.pack(pady=5)
        
        # Log File Selection
        file_frame = tk.LabelFrame(
            left_panel,
            text="📁 Log Files",
            bg=self.colors['bg5'],
            fg=self.colors['text'],
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        file_frame.pack(fill='x', pady=10, padx=10)
        
        self.log_file_var = tk.StringVar()
        self.log_file_combo = ttk.Combobox(
            file_frame,
            textvariable=self.log_file_var,
            state='readonly',
            width=25
        )
        self.log_file_combo.pack(pady=5)
        
        self.load_log_btn = tk.Button(
            file_frame,
            text="📂 Load Selected Log",
            font=("Arial", 10, "bold"),
            bg=self.colors['bg3'],
            fg=self.colors['text'],
            command=self.load_log_file
        )
        self.load_log_btn.pack(fill='x', pady=5)
        
        # Integrity Monitoring
        monitor_frame = tk.LabelFrame(
            left_panel,
            text="🔍 Integrity Monitoring",
            bg=self.colors['bg5'],
            fg=self.colors['text'],
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        monitor_frame.pack(fill='x', pady=10, padx=10)
        
        self.monitor_status_label = tk.Label(
            monitor_frame,
            text="Monitoring: Inactive",
            font=("Arial", 10),
            bg=self.colors['bg5'],
            fg=self.colors['text']
        )
        self.monitor_status_label.pack(pady=5)
        
        self.start_monitor_btn = tk.Button(
            monitor_frame,
            text="▶️ Start Monitoring",
            font=("Arial", 10, "bold"),
            bg=self.colors['bg1'],
            fg=self.colors['text'],
            command=self.toggle_monitoring
        )
        self.start_monitor_btn.pack(fill='x', pady=5)
        
        # Search/Filter Section
        search_frame = tk.LabelFrame(
            left_panel,
            text="🔎 Search Logs",
            bg=self.colors['bg5'],
            fg=self.colors['text'],
            font=("Arial", 11, "bold"),
            padx=10,
            pady=10
        )
        search_frame.pack(fill='x', pady=10, padx=10)
        
        self.search_var = tk.StringVar()
        # Fixed: Use trace_add instead of trace to avoid deprecation warning
        self.search_var.trace_add('write', self.search_logs)
        
        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            font=("Arial", 10),
            bg='white',
            fg=self.colors['text']
        )
        search_entry.pack(fill='x', pady=5)
        
        self.search_results_label = tk.Label(
            search_frame,
            text="",
            font=("Arial", 9),
            bg=self.colors['bg5'],
            fg=self.colors['text']
        )
        self.search_results_label.pack(pady=5)
        
        # ========== RIGHT PANEL WIDGETS ==========
        
        # Log display with tabs for different views
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill='both', expand=True)
        
        # Log Viewer Tab
        log_tab = tk.Frame(self.notebook, bg=self.colors['bg4'])
        self.notebook.add(log_tab, text="📋 Log Viewer")
        
        # Log display area
        self.log_display = scrolledtext.ScrolledText(
            log_tab,
            wrap=tk.WORD,
            font=("Courier", 10),
            bg='white',
            fg=self.colors['text'],
            height=30
        )
        self.log_display.pack(fill='both', expand=True, padx=5, pady=5)
        self.log_display.config(state='disabled')
        
        # Alerts Tab
        alerts_tab = tk.Frame(self.notebook, bg=self.colors['bg4'])
        self.notebook.add(alerts_tab, text="🚨 Security Alerts")
        
        self.alerts_display = scrolledtext.ScrolledText(
            alerts_tab,
            wrap=tk.WORD,
            font=("Courier", 10),
            bg='white',
            fg=self.colors['text'],
            height=30
        )
        self.alerts_display.pack(fill='both', expand=True, padx=5, pady=5)
        self.alerts_display.config(state='disabled')
        
        # Status bar
        status_bar = tk.Frame(self.root, bg=self.colors['bg2'], height=30)
        status_bar.pack(side='bottom', fill='x')
        
        self.status_label = tk.Label(
            status_bar,
            text="Ready",
            bg=self.colors['bg2'],
            fg=self.colors['text'],
            font=("Arial", 9)
        )
        self.status_label.pack(side='left', padx=10)
        
    def setup_log_files(self):
        """Create sample log files if they don't exist"""
        log_dir = "../logs"
        os.makedirs(log_dir, exist_ok=True)
        
        log_files = {
            "system_audit.txt": self.generate_system_logs(),
            "security_events.txt": self.generate_security_logs(),
            "application_logs.txt": self.generate_application_logs(),
            "network_logs.txt": self.generate_network_logs()
        }
        
        for filename, content in log_files.items():
            filepath = os.path.join(log_dir, filename)
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(content)
        
        # Update combobox with log files
        log_files_list = [f for f in os.listdir(log_dir) if f.endswith('.txt')]
        self.log_file_combo['values'] = log_files_list
        if log_files_list:
            self.log_file_combo.set(log_files_list[0])
    
    def generate_system_logs(self):
        """Generate sample system audit logs"""
        logs = []
        for i in range(1, 101):
            timestamp = f"2024-02-{13 + (i%20):02d} {8 + (i%12):02d}:{(i*3)%60:02d}:{(i*7)%60:02d}"
            event = [
                f"[{timestamp}] SYSTEM: User login attempt - User: admin{i%10}, IP: 192.168.1.{i%255}",
                f"[{timestamp}] KERNEL: Process {1000+i} started - PID: {10000+i}",
                f"[{timestamp}] SYSTEM: Memory usage at {(50 + i%30)}%",
                f"[{timestamp}] SERVICE: Cron job #{i} executed successfully",
                f"[{timestamp}] SYSTEM: Disk usage: / {(30 + i%60)}% used"
            ]
            logs.append(event[i % len(event)])
        
        return "\n".join(logs)
    
    def generate_security_logs(self):
        """Generate sample security logs"""
        logs = []
        for i in range(1, 101):
            timestamp = f"2024-02-{13 + (i%20):02d} {8 + (i%12):02d}:{(i*3)%60:02d}:{(i*7)%60:02d}"
            event = [
                f"[{timestamp}] SECURITY: Failed login attempt - User: unknown, IP: 10.0.0.{i%255}",
                f"[{timestamp}] SECURITY: Firewall rule #{1000+i} updated",
                f"[{timestamp}] SECURITY: Port scan detected from 192.168.2.{i%255}",
                f"[{timestamp}] SECURITY: SSL certificate will expire in {30 - i%30} days",
                f"[{timestamp}] SECURITY: New SSH connection established from 10.0.1.{i%255}"
            ]
            logs.append(event[i % len(event)])
        
        return "\n".join(logs)
    
    def generate_application_logs(self):
        """Generate sample application logs"""
        logs = []
        for i in range(1, 101):
            timestamp = f"2024-02-{13 + (i%20):02d} {8 + (i%12):02d}:{(i*3)%60:02d}:{(i*7)%60:02d}"
            event = [
                f"[{timestamp}] APP: Application '{['web', 'db', 'cache'][i%3]}' started",
                f"[{timestamp}] APP: Database query executed in {(i%1000)}ms",
                f"[{timestamp}] APP: User '{['john', 'jane', 'bob'][i%3]}' performed action #{i}",
                f"[{timestamp}] APP: Cache hit ratio: {70 + i%25}%",
                f"[{timestamp}] APP: API call to /api/v{1 + i%3}/data successful"
            ]
            logs.append(event[i % len(event)])
        
        return "\n".join(logs)
    
    def generate_network_logs(self):
        """Generate sample network logs"""
        logs = []
        for i in range(1, 101):
            timestamp = f"2024-02-{13 + (i%20):02d} {8 + (i%12):02d}:{(i*3)%60:02d}:{(i*7)%60:02d}"
            event = [
                f"[{timestamp}] NETWORK: Connection from 10.0.0.{i%255}:{8000+i} to 10.0.1.10:80",
                f"[{timestamp}] NETWORK: Bandwidth usage: {(i%100)} Mbps",
                f"[{timestamp}] NETWORK: Packet loss: {i%5}% on interface eth0",
                f"[{timestamp}] NETWORK: DNS query for host{i}.local resolved in {i%200}ms",
                f"[{timestamp}] NETWORK: TCP connection timeout from 192.168.1.{i%255}"
            ]
            logs.append(event[i % len(event)])
        
        return "\n".join(logs)
    
    def start_server(self):
        """Start the server process"""
        try:
            # First check if server is already running
            if self.check_server_running():
                messagebox.showinfo("Server Status", "Server is already running!")
                self.server_status_label.config(text="Server: Running", fg='green')
                self.start_server_btn.config(state='disabled')
                self.connect_btn.config(state='normal')
                self.connection_status_label.config(text="Ready to Connect", fg='blue')
                return
            
            # Run server in a separate process
            self.server_process = subprocess.Popen(
                [sys.executable, "src/server_vault.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            self.server_status_label.config(text="Server: Starting...", fg='orange')
            self.start_server_btn.config(state='disabled')
            
            # Wait for server to start
            self.root.after(2000, self.check_server_ready)
            
            self.update_status("Server starting...")
            
            # Start thread to read server output
            threading.Thread(target=self.read_server_output, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to start server: {e}")
            self.server_status_label.config(text="Server: Failed", fg='red')
            self.start_server_btn.config(state='normal')
    
    def check_server_ready(self):
        """Check if server is ready and enable connection button"""
        if self.check_server_running():
            self.server_status_label.config(text="Server: Running", fg='green')
            self.connect_btn.config(state='normal')
            self.connection_status_label.config(text="Ready to Connect", fg='blue')
            self.update_status("Server is ready")
        else:
            # Try again after 2 seconds
            self.root.after(2000, self.check_server_ready)
    
    def check_server_running(self):
        """Check if server is actually running by attempting a connection"""
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(1)
            result = test_socket.connect_ex(('127.0.0.1', 9999))
            test_socket.close()
            return result == 0
        except:
            return False
    
    def read_server_output(self):
        """Read and display server output"""
        if self.server_process:
            for line in self.server_process.stdout:
                if line:
                    self.root.after(0, lambda l=line: self.update_alerts(f"SERVER: {l.strip()}"))
    
    def connect_to_server(self):
        """Connect to the server"""
        try:
            # Try to connect with timeout
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)
            self.client_socket.connect(('127.0.0.1', 9999))
            
            self.connection_status_label.config(text="Connected", fg='green')
            self.connect_btn.config(state='disabled', text="✅ Connected")
            self.update_status("Connected to server")
            
            # Start heartbeat thread
            self.start_heartbeat()
            
        except socket.timeout:
            messagebox.showerror("Connection Error", "Connection timeout - server not responding")
            self.connection_status_label.config(text="Connection Failed", fg='red')
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", 
                               "Cannot connect to server. Please make sure the server is started first.\n\n"
                               "1. Click 'Start Server' button\n"
                               "2. Wait for 'Server: Running' status\n"
                               "3. Then click 'Connect to Server'")
            self.connection_status_label.config(text="Server Not Ready", fg='red')
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            self.connection_status_label.config(text="Connection Failed", fg='red')
    
    def start_heartbeat(self):
        """Start sending heartbeats to server"""
        if self.heartbeat_thread_running:
            return
        
        self.heartbeat_thread_running = True
        
        def heartbeat_loop():
            while self.heartbeat_thread_running and self.client_socket:
                try:
                    if self.current_log_file and self.monitoring:
                        file_hash = self.security_utils.calculate_file_hash(self.current_log_file)
                        
                        heartbeat = {
                            'log_file': os.path.basename(self.current_log_file),
                            'file_hash': file_hash,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        self.client_socket.send(json.dumps(heartbeat).encode())
                        
                        # Check for server response
                        self.client_socket.settimeout(2)
                        try:
                            response = self.client_socket.recv(1024).decode()
                            if response:
                                response_data = json.loads(response)
                                if response_data.get('alert_detected'):
                                    self.root.after(0, self.show_alert, "Tampering detected by server!")
                        except socket.timeout:
                            pass
                        
                    time.sleep(5)  # Send heartbeat every 5 seconds
                    
                except (socket.error, BrokenPipeError):
                    # Connection lost
                    self.heartbeat_thread_running = False
                    self.root.after(0, self.handle_disconnection)
                    break
                except Exception as e:
                    print(f"Heartbeat error: {e}")
                    time.sleep(5)
        
        threading.Thread(target=heartbeat_loop, daemon=True).start()
    
    def handle_disconnection(self):
        """Handle server disconnection"""
        self.connection_status_label.config(text="Disconnected", fg='red')
        self.connect_btn.config(state='normal', text="🔌 Connect to Server")
        self.monitoring = False
        self.monitor_status_label.config(text="Monitoring: Inactive", fg=self.colors['text'])
        self.start_monitor_btn.config(text="▶️ Start Monitoring", bg=self.colors['bg1'])
        self.update_status("Disconnected from server")
        self.update_alerts("⚠️ Disconnected from server")
    
    def load_log_file(self):
        """Load selected log file"""
        filename = self.log_file_var.get()
        if not filename:
            return
        
        filepath = os.path.join("../logs", filename)
        
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Update circular buffer
            self.log_buffer = CircularLogBuffer(max_size=100)  # Reset buffer
            for line in content.split('\n'):
                if line.strip():
                    self.log_buffer.add_log(line)
            
            # Display in GUI
            self.log_display.config(state='normal')
            self.log_display.delete(1.0, tk.END)
            self.log_display.insert(1.0, content)
            self.log_display.config(state='disabled')
            
            self.current_log_file = filepath
            self.last_hash = self.security_utils.calculate_file_hash(filepath)
            
            self.update_status(f"Loaded {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {e}")
    
    def toggle_monitoring(self):
        """Toggle integrity monitoring"""
        if not self.current_log_file:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        if not self.client_socket or self.connection_status_label.cget('text') != "Connected":
            messagebox.showwarning("Warning", "Please connect to server first")
            return
        
        self.monitoring = not self.monitoring
        
        if self.monitoring:
            self.monitor_status_label.config(text="Monitoring: Active", fg='green')
            self.start_monitor_btn.config(text="⏸️ Stop Monitoring", bg=self.colors['bg2'])
            self.update_status("Monitoring started - will detect file changes")
            # Start monitoring thread
            threading.Thread(target=self.monitor_integrity, daemon=True).start()
        else:
            self.monitor_status_label.config(text="Monitoring: Inactive", fg=self.colors['text'])
            self.start_monitor_btn.config(text="▶️ Start Monitoring", bg=self.colors['bg1'])
            self.update_status("Monitoring stopped")
    
    def monitor_integrity(self):
        """Monitor file integrity"""
        while self.monitoring and self.current_log_file:
            try:
                current_hash = self.security_utils.calculate_file_hash(self.current_log_file)
                
                if current_hash != self.last_hash:
                    # Tamper detected!
                    self.root.after(0, self.show_tamper_alert)
                    self.last_hash = current_hash
                
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                print(f"Integrity check error: {e}")
                time.sleep(2)
    
    def show_tamper_alert(self):
        """Show tamper detection alert"""
        alert_msg = f"⚠️ SECURITY ALERT: Log file has been modified!\nFile: {os.path.basename(self.current_log_file)}\nTime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        self.update_alerts(alert_msg)
        
        # Flash the window
        self.root.attributes('-alpha', 0.5)
        self.root.after(200, lambda: self.root.attributes('-alpha', 1.0))
        
        # Show popup
        messagebox.showwarning("Tamper Detected!", alert_msg)
    
    def show_alert(self, message):
        """Show general alert"""
        self.update_alerts(f"🚨 {message}")
    
    def search_logs(self, *args):
        """Search logs for keyword"""
        keyword = self.search_var.get().strip()
        
        if not keyword or not self.current_log_file:
            self.search_results_label.config(text="")
            # Remove highlighting
            if hasattr(self, 'log_display'):
                self.log_display.config(state='normal')
                self.log_display.tag_remove('highlight', '1.0', tk.END)
                self.log_display.config(state='disabled')
            return
        
        try:
            with open(self.current_log_file, 'r') as f:
                lines = f.readlines()
            
            # Search in circular buffer as well
            buffer_results = self.log_buffer.search_logs(keyword)
            
            # Search in file
            file_results = [line.strip() for line in lines if keyword.lower() in line.lower()]
            
            total_results = len(set(buffer_results + file_results))
            
            self.search_results_label.config(text=f"Found {total_results} matches")
            
            # Highlight in display
            self.log_display.config(state='normal')
            
            # Remove previous highlighting
            self.log_display.tag_remove('highlight', '1.0', tk.END)
            
            # Add highlighting
            start_pos = '1.0'
            while True:
                start_pos = self.log_display.search(keyword, start_pos, tk.END, nocase=True)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(keyword)}c"
                self.log_display.tag_add('highlight', start_pos, end_pos)
                start_pos = end_pos
            
            self.log_display.tag_config('highlight', background='yellow', foreground='black')
            self.log_display.config(state='disabled')
            
        except Exception as e:
            print(f"Search error: {e}")
    
    def update_alerts(self, message):
        """Update alerts display"""
        self.alerts_display.config(state='normal')
        self.alerts_display.insert('end', f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.alerts_display.see('end')
        self.alerts_display.config(state='disabled')
    
    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=message)
    
    def run(self):
        """Run the main application"""
        self.root.mainloop()
    
    def on_closing(self):
        """Clean up on close"""
        self.heartbeat_thread_running = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=3)
            except:
                self.server_process.kill()
        
        self.root.destroy()

def main():
    """Main entry point"""
    login = LoginWindow()
    login.run()

if __name__ == "__main__":
    main()