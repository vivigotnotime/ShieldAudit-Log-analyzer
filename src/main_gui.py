"""
main_gui.py
Purpose: Main client application with Tkinter GUI and role-based access control
Features: Login/Logout, Persistent server, Role-based permissions
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

# Global server process (persists across logins)
SERVER_PROCESS = None
SERVER_THREAD = None
SERVER_RUNNING = False

class LoginWindow:
    """Login window for user authentication"""
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("ShieldAudit - Login")
        self.window.geometry("450x600")
        self.window.configure(bg='#abb1cf')
        
        # Center the window
        self.window.eval('tk::PlaceWindow . center')
        
        # User credentials with explicit permissions
        self.users = {
            'admin': {
                'password': 'admin123',
                'role': 'Administrator',
                'permissions': {
                    'start_server': True,
                    'stop_server': True,
                    'connect_server': True,
                    'load_logs': True,
                    'start_monitoring': True,
                    'stop_monitoring': True,
                    'search_logs': True,
                    'view_alerts': True,
                    'configure_settings': True,
                    'manage_users': True
                },
                'purpose': 'Full system administration - can perform all actions',
                'color': '#e17369'  # Red
            },
            'auditor': {
                'password': 'audit123',
                'role': 'Security Auditor',
                'permissions': {
                    'start_server': False,
                    'stop_server': False,
                    'connect_server': False,
                    'load_logs': True,
                    'start_monitoring': False,
                    'stop_monitoring': False,
                    'search_logs': True,
                    'view_alerts': True,
                    'configure_settings': False,
                    'manage_users': False
                },
                'purpose': 'View logs and alerts only - cannot modify system state',
                'color': '#92a8d1'  # Blue
            },
            'analyst': {
                'password': 'analyze123',
                'role': 'Log Analyst',
                'permissions': {
                    'start_server': False,
                    'stop_server': False,
                    'connect_server': True,
                    'load_logs': True,
                    'start_monitoring': True,
                    'stop_monitoring': True,
                    'search_logs': True,
                    'view_alerts': True,
                    'configure_settings': False,
                    'manage_users': False
                },
                'purpose': 'Analyze logs and monitor integrity - cannot start/stop server',
                'color': '#f3b2ad'  # Pink
            }
        }
        
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title_label = tk.Label(
            self.window,
            text="🔒 ShieldAudit",
            font=("Arial", 28, "bold"),
            bg='#abb1cf',
            fg='#2d2d2d'
        )
        title_label.pack(pady=30)
        
        subtitle_label = tk.Label(
            self.window,
            text="Secure Distributed Log Integrity Guard",
            font=("Arial", 11),
            bg='#abb1cf',
            fg='#2d2d2d'
        )
        subtitle_label.pack(pady=10)
        
        # Server status indicator
        server_frame = tk.Frame(self.window, bg='#abb1cf')
        server_frame.pack(pady=10)
        
        global SERVER_RUNNING
        server_status_text = "🟢 Server Running" if SERVER_RUNNING else "🔴 Server Stopped"
        server_status_color = "green" if SERVER_RUNNING else "red"
        
        self.server_status_label = tk.Label(
            server_frame,
            text=server_status_text,
            font=("Arial", 10, "bold"),
            bg='#abb1cf',
            fg=server_status_color
        )
        self.server_status_label.pack()
        
        # Login frame
        login_frame = tk.Frame(self.window, bg='#92a8d1', padx=30, pady=30)
        login_frame.pack(pady=20, padx=50, fill='both')
        
        # Username
        tk.Label(
            login_frame,
            text="Username:",
            font=("Arial", 12),
            bg='#92a8d1',
            fg='#2d2d2d'
        ).pack(anchor='w', pady=(0,5))
        
        self.username_var = tk.StringVar(value="admin")
        username_entry = tk.Entry(
            login_frame,
            textvariable=self.username_var,
            font=("Arial", 12),
            width=25,
            bg='white',
            fg='#2d2d2d'
        )
        username_entry.pack(pady=(0,15))
        
        # Password
        tk.Label(
            login_frame,
            text="Password:",
            font=("Arial", 12),
            bg='#92a8d1',
            fg='#2d2d2d'
        ).pack(anchor='w', pady=(0,5))
        
        self.password_var = tk.StringVar(value="admin123")
        password_entry = tk.Entry(
            login_frame,
            textvariable=self.password_var,
            font=("Arial", 12),
            width=25,
            show="*",
            bg='white',
            fg='#2d2d2d'
        )
        password_entry.pack(pady=(0,20))
        
        # Login button
        login_btn = tk.Button(
            login_frame,
            text="Login",
            font=("Arial", 12, "bold"),
            bg='#e17369',
            fg='#2d2d2d',
            padx=30,
            pady=8,
            command=self.login,
            cursor="hand2"
        )
        login_btn.pack(pady=10)
        
        # User info section
        info_frame = tk.Frame(self.window, bg='#abb1cf')
        info_frame.pack(pady=10, fill='both', expand=True, padx=20)
        
        tk.Label(
            info_frame,
            text="📋 Demo Credentials & Permissions",
            font=("Arial", 12, "bold"),
            bg='#abb1cf',
            fg='#2d2d2d'
        ).pack(pady=10)
        
        # Create a canvas with scrollbar for user info
        canvas = tk.Canvas(info_frame, bg='#abb1cf', highlightthickness=0)
        scrollbar = tk.Scrollbar(info_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#abb1cf')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Display user credentials with permissions
        for username, data in self.users.items():
            # User card
            card_frame = tk.Frame(scrollable_frame, bg=data['color'], padx=15, pady=10)
            card_frame.pack(fill='x', pady=5, padx=5)
            
            # Username and role
            tk.Label(
                card_frame,
                text=f"👤 {username.upper()} - {data['role']}",
                font=("Arial", 11, "bold"),
                bg=data['color'],
                fg='#2d2d2d'
            ).pack(anchor='w')
            
            # Password
            tk.Label(
                card_frame,
                text=f"🔑 Password: {data['password']}",
                font=("Arial", 10),
                bg=data['color'],
                fg='#2d2d2d'
            ).pack(anchor='w', pady=(2,5))
            
            # Purpose
            tk.Label(
                card_frame,
                text=f"📌 {data['purpose']}",
                font=("Arial", 9, "italic"),
                bg=data['color'],
                fg='#2d2d2d',
                wraplength=300,
                justify='left'
            ).pack(anchor='w', pady=(0,5))
            
            # Permissions
            perm_text = "✓ " + ", ".join([k.replace('_', ' ').title() 
                                         for k, v in data['permissions'].items() if v])
            tk.Label(
                card_frame,
                text=perm_text,
                font=("Arial", 8),
                bg=data['color'],
                fg='#2d2d2d',
                wraplength=300,
                justify='left'
            ).pack(anchor='w')
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def login(self):
        username = self.username_var.get()
        password = self.password_var.get()
        
        if username in self.users and self.users[username]['password'] == password:
            self.window.withdraw()  # Hide login window
            # Open main application with user permissions
            app = ShieldAuditGUI(self.users[username], self)
            app.run()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")
    
    def show_login(self):
        """Show login window again after logout"""
        global SERVER_RUNNING
        # Update server status
        server_status_text = "🟢 Server Running" if SERVER_RUNNING else "🔴 Server Stopped"
        server_status_color = "green" if SERVER_RUNNING else "red"
        self.server_status_label.config(text=server_status_text, fg=server_status_color)
        
        self.window.deiconify()  # Show login window
    
    def run(self):
        self.window.mainloop()

class ShieldAuditGUI:
    """Main GUI Application with Role-Based Access Control"""
    def __init__(self, user_info, login_window):
        self.user = user_info
        self.login_window = login_window
        self.permissions = user_info['permissions']
        self.root = tk.Toplevel()
        self.root.title(f"ShieldAudit - Logged in as {user_info['role']}")
        self.root.geometry("1400x800")
        self.root.configure(bg='#abb1cf')
        
        # Initialize components
        self.log_buffer = CircularLogBuffer(max_size=100)
        self.security_utils = SecurityUtils()
        self.current_log_file = None
        self.monitoring = False
        self.last_hash = None
        self.client_socket = None
        self.heartbeat_thread_running = False
        
        # Color scheme
        self.colors = {
            'bg1': '#e17369',
            'bg2': '#e95f69',
            'bg3': '#f3b2ad',
            'bg4': '#abb1cf',
            'bg5': '#92a8d1',
            'text': '#2d2d2d',
            'disabled': '#888888'  # Gray for disabled buttons
        }
        
        self.create_widgets()
        self.setup_log_files()
        self.check_server_status()
        self.apply_role_based_restrictions()
        
        # Set up protocol for window closing
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def check_server_status(self):
        """Check and display server status"""
        global SERVER_RUNNING
        if SERVER_RUNNING:
            self.server_status_label.config(text="Server: Running", fg='green')
            if self.permissions.get('connect_server', False):
                self.connect_btn.config(state='normal')
            self.connection_status_label.config(text="Ready to Connect", fg='blue')
        else:
            self.server_status_label.config(text="Server: Stopped", fg='red')
    
    def apply_role_based_restrictions(self):
        """Apply role-based access control to GUI elements"""
        print(f"\n🔐 Applying role-based restrictions for: {self.user['role']}")
        
        # Server Control Section
        if not self.permissions.get('start_server', False):
            self.start_server_btn.config(state='disabled', bg=self.colors['disabled'])
            self.start_server_btn.config(text="🚫 Start Server (Admin Only)")
        
        if not self.permissions.get('stop_server', False):
            self.stop_server_btn.config(state='disabled', bg=self.colors['disabled'])
            self.stop_server_btn.config(text="🛑 Stop Server (Admin Only)")
        
        if not self.permissions.get('connect_server', False):
            self.connect_btn.config(state='disabled', bg=self.colors['disabled'])
            self.connect_btn.config(text="🔌 Connect (Auditor cannot connect)")
        
        # Monitoring Section
        if not self.permissions.get('start_monitoring', False):
            self.start_monitor_btn.config(state='disabled', bg=self.colors['disabled'])
            self.start_monitor_btn.config(text="▶️ Monitoring (View Only)")
        
        # Display role summary
        enabled = [k for k, v in self.permissions.items() if v]
        disabled = [k for k, v in self.permissions.items() if not v]
        print(f"  Enabled: {', '.join(enabled)}")
        print(f"  Disabled: {', '.join(disabled)}")
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = tk.Frame(self.root, bg=self.colors['bg4'])
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left panel - Controls
        left_panel = tk.Frame(main_frame, bg=self.colors['bg5'], width=320)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Right panel - Log display
        right_panel = tk.Frame(main_frame, bg=self.colors['bg4'])
        right_panel.pack(side='right', fill='both', expand=True)
        
        # ========== LEFT PANEL WIDGETS ==========
        
        # User info with role badge and logout button
        user_frame = tk.Frame(left_panel, bg=self.colors['bg5'])
        user_frame.pack(fill='x', pady=10, padx=10)
        
        # Role badge with color coding
        role_colors = {
            'Administrator': '#e17369',
            'Security Auditor': '#92a8d1',
            'Log Analyst': '#f3b2ad'
        }
        role_color = role_colors.get(self.user['role'], self.colors['bg2'])
        
        role_badge = tk.Frame(user_frame, bg=role_color, padx=10, pady=5)
        role_badge.pack(fill='x')
        
        tk.Label(
            role_badge,
            text=f"👤 {self.user['role']}",
            font=("Arial", 12, "bold"),
            bg=role_color,
            fg='#2d2d2d'
        ).pack(side='left')
        
        # Logout button
        logout_btn = tk.Button(
            role_badge,
            text="🚪 Logout",
            font=("Arial", 9, "bold"),
            bg='#2d2d2d',
            fg='white',
            command=self.logout,
            cursor="hand2"
        )
        logout_btn.pack(side='right')
        
        # Permission summary
        perm_text = []
        if self.permissions.get('start_server', False):
            perm_text.append("✓ Can start/stop server")
        if self.permissions.get('connect_server', False):
            perm_text.append("✓ Can connect to server")
        if self.permissions.get('start_monitoring', False):
            perm_text.append("✓ Can monitor logs")
        if self.permissions.get('search_logs', False):
            perm_text.append("✓ Can search logs")
        
        tk.Label(
            user_frame,
            text="\n".join(perm_text),
            font=("Arial", 9),
            bg=self.colors['bg5'],
            fg='#2d2d2d',
            justify='left'
        ).pack(pady=5)
        
        tk.Label(
            user_frame,
            text=f"Purpose: {self.user['purpose']}",
            font=("Arial", 9, "italic"),
            bg=self.colors['bg5'],
            fg='#2d2d2d',
            wraplength=280
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
            font=("Arial", 10, "bold"),
            bg=self.colors['bg5'],
            fg='red'
        )
        self.server_status_label.pack(pady=5)
        
        # Server control buttons frame
        server_btn_frame = tk.Frame(server_frame, bg=self.colors['bg5'])
        server_btn_frame.pack(fill='x', pady=5)
        
        self.start_server_btn = tk.Button(
            server_btn_frame,
            text="🚀 Start",
            font=("Arial", 10, "bold"),
            bg=self.colors['bg1'],
            fg=self.colors['text'],
            command=self.start_server,
            width=10,
            cursor="hand2"
        )
        self.start_server_btn.pack(side='left', padx=2)
        
        self.stop_server_btn = tk.Button(
            server_btn_frame,
            text="🛑 Stop",
            font=("Arial", 10, "bold"),
            bg=self.colors['bg2'],
            fg=self.colors['text'],
            command=self.stop_server,
            width=10,
            cursor="hand2",
            state='disabled'
        )
        self.stop_server_btn.pack(side='left', padx=2)
        
        self.connect_btn = tk.Button(
            server_frame,
            text="🔌 Connect to Server",
            font=("Arial", 10, "bold"),
            bg=self.colors['bg3'],
            fg=self.colors['text'],
            command=self.connect_to_server,
            cursor="hand2",
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
            width=28
        )
        self.log_file_combo.pack(pady=5)
        
        self.load_log_btn = tk.Button(
            file_frame,
            text="📂 Load Selected Log",
            font=("Arial", 10, "bold"),
            bg=self.colors['bg1'],
            fg=self.colors['text'],
            command=self.load_log_file,
            cursor="hand2"
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
            bg=self.colors['bg2'],
            fg=self.colors['text'],
            command=self.toggle_monitoring,
            cursor="hand2"
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
        
        # Role indicator in status bar
        role_indicator = tk.Label(
            status_bar,
            text=f"Logged in as: {self.user['role']}",
            bg=self.colors['bg2'],
            fg=self.colors['text'],
            font=("Arial", 9, "bold")
        )
        role_indicator.pack(side='right', padx=10)
    
    def logout(self):
        """Logout current user and return to login screen"""
        # Stop monitoring if active
        if self.monitoring:
            self.monitoring = False
            self.heartbeat_thread_running = False
        
        # Close client socket if connected
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        
        # Destroy current window
        self.root.destroy()
        
        # Show login window again
        self.login_window.show_login()
    
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
        """Start the server process - Admin only"""
        global SERVER_PROCESS, SERVER_RUNNING
        
        if not self.permissions.get('start_server', False):
            messagebox.showerror("Access Denied", 
                               "You don't have permission to start the server.\n"
                               "Only Administrators can control the server.")
            return
        
        if SERVER_RUNNING:
            messagebox.showinfo("Server Status", "Server is already running!")
            return
        
        try:
            # Run server in a separate process
            SERVER_PROCESS = subprocess.Popen(
                [sys.executable, "src/server_vault.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            SERVER_RUNNING = True
            self.server_status_label.config(text="Server: Starting...", fg='orange')
            self.start_server_btn.config(state='disabled')
            self.stop_server_btn.config(state='normal')
            
            # Wait for server to start
            self.root.after(2000, self.check_server_ready)
            
            self.update_status("Server starting...")
            self.update_alerts("🟢 Server starting...")
            
            # Start thread to read server output
            threading.Thread(target=self.read_server_output, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Server Error", f"Failed to start server: {e}")
            SERVER_RUNNING = False
            self.server_status_label.config(text="Server: Failed", fg='red')
            if self.permissions.get('start_server', False):
                self.start_server_btn.config(state='normal')
    
    def stop_server(self):
        """Stop the server process - Admin only"""
        global SERVER_PROCESS, SERVER_RUNNING
        
        if not self.permissions.get('stop_server', False):
            messagebox.showerror("Access Denied", 
                               "You don't have permission to stop the server.\n"
                               "Only Administrators can control the server.")
            return
        
        if not SERVER_RUNNING:
            messagebox.showinfo("Server Status", "Server is not running!")
            return
        
        # Confirm with user
        if messagebox.askyesno("Confirm", "Are you sure you want to stop the server?\nAll connected clients will be disconnected."):
            try:
                if SERVER_PROCESS:
                    SERVER_PROCESS.terminate()
                    SERVER_PROCESS.wait(timeout=5)
                
                SERVER_RUNNING = False
                self.server_status_label.config(text="Server: Stopped", fg='red')
                self.start_server_btn.config(state='normal')
                self.stop_server_btn.config(state='disabled')
                self.connect_btn.config(state='disabled')
                self.connection_status_label.config(text="Not Connected", fg='red')
                
                self.update_status("Server stopped")
                self.update_alerts("🔴 Server stopped")
                
                # Close client connection if any
                if self.client_socket:
                    self.client_socket.close()
                    self.client_socket = None
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop server: {e}")
    
    def check_server_ready(self):
        """Check if server is ready and enable connection button"""
        if self.check_server_running():
            self.server_status_label.config(text="Server: Running", fg='green')
            if self.permissions.get('connect_server', False):
                self.connect_btn.config(state='normal')
            self.connection_status_label.config(text="Ready to Connect", fg='blue')
            self.update_status("Server is ready")
            self.update_alerts("🟢 Server is ready")
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
        global SERVER_PROCESS
        if SERVER_PROCESS:
            for line in SERVER_PROCESS.stdout:
                if line:
                    self.root.after(0, lambda l=line: self.update_alerts(f"SERVER: {l.strip()}"))
    
    def connect_to_server(self):
        """Connect to the server - Admin and Analyst only"""
        global SERVER_RUNNING
        
        if not self.permissions.get('connect_server', False):
            messagebox.showerror("Access Denied", 
                               "You don't have permission to connect to the server.\n"
                               "Auditors can only view existing logs, not connect.")
            return
        
        if not SERVER_RUNNING:
            messagebox.showerror("Connection Error", "Server is not running. Please start the server first.")
            return
        
        try:
            # Try to connect with timeout
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(5)
            self.client_socket.connect(('127.0.0.1', 9999))
            
            self.connection_status_label.config(text="Connected", fg='green')
            self.connect_btn.config(state='disabled', text="✅ Connected")
            self.update_status("Connected to server")
            self.update_alerts("✅ Connected to server")
            
            # Start heartbeat thread if monitoring is allowed
            if self.permissions.get('start_monitoring', False):
                self.start_heartbeat()
            
        except socket.timeout:
            messagebox.showerror("Connection Error", "Connection timeout - server not responding")
            self.connection_status_label.config(text="Connection Failed", fg='red')
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", 
                               "Cannot connect to server. Please make sure the server is running.")
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
        if self.permissions.get('connect_server', False):
            self.connect_btn.config(state='normal', text="🔌 Connect to Server")
        self.monitoring = False
        self.monitor_status_label.config(text="Monitoring: Inactive", fg=self.colors['text'])
        self.start_monitor_btn.config(text="▶️ Start Monitoring", bg=self.colors['bg2'])
        self.update_status("Disconnected from server")
        self.update_alerts("⚠️ Disconnected from server")
    
    def load_log_file(self):
        """Load selected log file - All roles can view logs"""
        if not self.permissions.get('load_logs', False):
            messagebox.showerror("Access Denied", "You don't have permission to view logs.")
            return
        
        filename = self.log_file_var.get()
        if not filename:
            return
        
        filepath = os.path.join("../logs", filename)
        
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Update circular buffer
            self.log_buffer = CircularLogBuffer(max_size=100)
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
        if not self.permissions.get('start_monitoring', False):
            messagebox.showerror("Access Denied", 
                               "You don't have permission to start monitoring.\n"
                               "Auditors can only view logs, not monitor them.")
            return
        
        if not self.current_log_file:
            messagebox.showwarning("Warning", "Please load a log file first")
            return
        
        if not self.client_socket or self.connection_status_label.cget('text') != "Connected":
            messagebox.showwarning("Warning", "Please connect to server first")
            return
        
        self.monitoring = not self.monitoring
        
        if self.monitoring:
            self.monitor_status_label.config(text="Monitoring: Active", fg='green')
            self.start_monitor_btn.config(text="⏸️ Stop Monitoring", bg=self.colors['bg1'])
            self.update_status("Monitoring started - will detect file changes")
            self.update_alerts("▶️ Monitoring started")
            # Start monitoring thread
            threading.Thread(target=self.monitor_integrity, daemon=True).start()
        else:
            self.monitor_status_label.config(text="Monitoring: Inactive", fg=self.colors['text'])
            self.start_monitor_btn.config(text="▶️ Start Monitoring", bg=self.colors['bg2'])
            self.update_status("Monitoring stopped")
            self.update_alerts("⏸️ Monitoring stopped")
    
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
        """Search logs for keyword - All roles can search"""
        if not self.permissions.get('search_logs', False):
            return
        
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
        """Update alerts display - All roles can view alerts"""
        if not self.permissions.get('view_alerts', False):
            return
        
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
        """Handle window closing - logout instead of exit"""
        self.logout()

def main():
    """Main entry point"""
    login = LoginWindow()
    login.run()

if __name__ == "__main__":
    main()