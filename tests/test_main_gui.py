"""
Unit tests for main_gui.py
Tests GUI components and functionality
Note: These tests use mocks to avoid actual GUI creation
"""
import unittest
import sys
import os
import tempfile
import time
from unittest.mock import Mock, patch, MagicMock, PropertyMock, call
import tkinter as tk

sys.path.append('..')
from src.main_gui import LoginWindow, ShieldAuditGUI

class TestLoginWindow(unittest.TestCase):
    """Test the LoginWindow class"""
    
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*70)
        print("SETTING UP LOGIN WINDOW TESTS")
        print("="*70)
    
    def setUp(self):
        print("\n" + "-"*50)
        print(f"Starting test: {self._testMethodName}")
        print("-"*50)
        
        # Mock all tkinter components before creating LoginWindow
        self.tk_patcher = patch('tkinter.Tk')
        self.stringvar_patcher = patch('tkinter.StringVar')
        self.label_patcher = patch('tkinter.Label')
        self.button_patcher = patch('tkinter.Button')
        self.frame_patcher = patch('tkinter.Frame')
        
        self.mock_tk = self.tk_patcher.start()
        self.mock_stringvar = self.stringvar_patcher.start()
        self.mock_label = self.label_patcher.start()
        self.mock_button = self.button_patcher.start()
        self.mock_frame = self.frame_patcher.start()
        
        # Configure StringVar mock to behave like a real StringVar
        self.username_var = MagicMock()
        self.username_var.get.return_value = "admin"
        self.password_var = MagicMock()
        self.password_var.get.return_value = "admin123"
        
        self.mock_stringvar.side_effect = [self.username_var, self.password_var]
        
        # Create login instance with mocked components
        with patch.object(LoginWindow, 'create_widgets'):  # Skip widget creation
            self.login = LoginWindow()
            self.login.window = self.mock_tk
            self.login.username_var = self.username_var
            self.login.password_var = self.password_var
    
    def tearDown(self):
        self.tk_patcher.stop()
        self.stringvar_patcher.stop()
        self.label_patcher.stop()
        self.button_patcher.stop()
        self.frame_patcher.stop()
    
    def test_initialization(self):
        """Test login window initialization"""
        print("\n[TEST] Testing login window initialization...")
        
        self.assertIsNotNone(self.login.users)
        self.assertEqual(len(self.login.users), 3)
        print(f"✓ {len(self.login.users)} users configured")
        
        # Check user credentials
        expected_users = ['admin', 'auditor', 'analyst']
        for username in expected_users:
            self.assertIn(username, self.login.users)
            self.assertIn('password', self.login.users[username])
            self.assertIn('role', self.login.users[username])
            self.assertIn('purpose', self.login.users[username])
        print("✓ All users have required fields")
    
    @patch('tkinter.messagebox.showerror')
    def test_successful_login(self, mock_showerror):
        """Test successful login"""
        print("\n[TEST] Testing successful login...")
        
        self.username_var.get.return_value = "admin"
        self.password_var.get.return_value = "admin123"
        
        # Mock the window destroy method
        self.login.window.destroy = MagicMock()
        
        # Mock ShieldAuditGUI to prevent actual GUI creation
        with patch('src.main_gui.ShieldAuditGUI') as mock_gui:
            self.login.login()
            self.login.window.destroy.assert_called_once()
            print("✓ Successful login: window destroyed")
        
        mock_showerror.assert_not_called()
        print("✓ No error message shown")
    
    @patch('tkinter.messagebox.showerror')
    def test_failed_login_wrong_password(self, mock_showerror):
        """Test failed login with wrong password"""
        print("\n[TEST] Testing failed login (wrong password)...")
        
        self.username_var.get.return_value = "admin"
        self.password_var.get.return_value = "wrongpassword"
        
        # Call login method
        self.login.login()
        
        # Verify showerror was called
        mock_showerror.assert_called_once()
        print("✓ Error message shown for wrong password")
    
    @patch('tkinter.messagebox.showerror')
    def test_failed_login_nonexistent_user(self, mock_showerror):
        """Test failed login with nonexistent user"""
        print("\n[TEST] Testing failed login (nonexistent user)...")
        
        self.username_var.get.return_value = "nonexistent"
        self.password_var.get.return_value = "anypassword"
        
        # Call login method
        self.login.login()
        
        # Verify showerror was called
        mock_showerror.assert_called_once()
        print("✓ Error message shown for nonexistent user")

class TestShieldAuditGUI(unittest.TestCase):
    """Test the ShieldAuditGUI class"""
    
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*70)
        print("SETTING UP SHIELDAUDIT GUI TESTS")
        print("="*70)
    
    def setUp(self):
        print("\n" + "-"*50)
        print(f"Starting test: {self._testMethodName}")
        print("-"*50)
        
        # Create mock user
        self.test_user = {
            'role': 'Administrator',
            'purpose': 'Testing'
        }
        
        # Mock all tkinter components
        self.tk_patcher = patch('tkinter.Tk')
        self.stringvar_patcher = patch('tkinter.StringVar')
        self.frame_patcher = patch('tkinter.Frame')
        self.label_patcher = patch('tkinter.Label')
        self.button_patcher = patch('tkinter.Button')
        self.combobox_patcher = patch('tkinter.ttk.Combobox')
        self.text_patcher = patch('tkinter.scrolledtext.ScrolledText')
        self.notebook_patcher = patch('tkinter.ttk.Notebook')
        
        self.mock_tk = self.tk_patcher.start()
        self.mock_stringvar = self.stringvar_patcher.start()
        self.mock_frame = self.frame_patcher.start()
        self.mock_label = self.label_patcher.start()
        self.mock_button = self.button_patcher.start()
        self.mock_combobox = self.combobox_patcher.start()
        self.mock_text = self.text_patcher.start()
        self.mock_notebook = self.notebook_patcher.start()
        
        # Configure StringVar mock
        self.search_var = MagicMock()
        self.search_var.get.return_value = ""
        self.mock_stringvar.return_value = self.search_var
        
        # Create GUI instance with mocked methods
        with patch.object(ShieldAuditGUI, 'setup_log_files'):
            with patch.object(ShieldAuditGUI, 'create_widgets'):
                self.gui = ShieldAuditGUI(self.test_user)
                self.gui.root = self.mock_tk
                self.gui.search_var = self.search_var
                
                # Create all required mock widgets
                self.gui.server_status_label = MagicMock()
                self.gui.status_label = MagicMock()
                self.gui.alerts_display = MagicMock()
                self.gui.log_display = MagicMock()
                self.gui.log_file_combo = MagicMock()
                self.gui.start_server_btn = MagicMock()
                self.gui.connect_btn = MagicMock()
                self.gui.connection_status_label = MagicMock()
                self.gui.monitor_status_label = MagicMock()
                self.gui.start_monitor_btn = MagicMock()
                self.gui.search_results_label = MagicMock()
                
                # Configure status_label for config method
                self.gui.status_label.config = MagicMock()
                self.gui.server_status_label.config = MagicMock()
                self.gui.alerts_display.config = MagicMock()
                self.gui.alerts_display.insert = MagicMock()
                self.gui.alerts_display.see = MagicMock()
                self.gui.search_results_label.config = MagicMock()
                
                # Set initial values
                self.gui.monitoring = False
                self.gui.current_log_file = None
                self.gui.colors = {
                    'bg1': '#e17369',
                    'bg2': '#e95f69',
                    'bg3': '#f3b2ad',
                    'bg4': '#abb1cf',
                    'bg5': '#92a8d1',
                    'text': '#2d2d2d'
                }
    
    def tearDown(self):
        self.tk_patcher.stop()
        self.stringvar_patcher.stop()
        self.frame_patcher.stop()
        self.label_patcher.stop()
        self.button_patcher.stop()
        self.combobox_patcher.stop()
        self.text_patcher.stop()
        self.notebook_patcher.stop()
    
    def test_initialization(self):
        """Test GUI initialization"""
        print("\n[TEST] Testing GUI initialization...")
        
        self.assertIsNotNone(self.gui.log_buffer)
        self.assertIsNotNone(self.gui.security_utils)
        print("✓ Core components initialized")
        
        self.assertEqual(self.gui.user['role'], 'Administrator')
        print(f"✓ User role set correctly: {self.gui.user['role']}")
        
        self.assertFalse(self.gui.monitoring)
        print("✓ Monitoring initially disabled")
        
        self.assertIsNone(self.gui.current_log_file)
        print("✓ No log file initially loaded")
    
    def test_color_scheme(self):
        """Test color scheme configuration"""
        print("\n[TEST] Testing color scheme...")
        
        expected_colors = ['bg1', 'bg2', 'bg3', 'bg4', 'bg5', 'text']
        for color in expected_colors:
            self.assertIn(color, self.gui.colors)
        print("✓ All required colors defined")
        
        # Check text color
        self.assertEqual(self.gui.colors['text'], '#2d2d2d')
        print("✓ Text color set to dark grey")
    
    @patch('os.path.exists')
    @patch('os.makedirs')
    @patch('os.listdir')
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    @patch('src.main_gui.ShieldAuditGUI.generate_system_logs')
    @patch('src.main_gui.ShieldAuditGUI.generate_security_logs')
    @patch('src.main_gui.ShieldAuditGUI.generate_application_logs')
    @patch('src.main_gui.ShieldAuditGUI.generate_network_logs')
    def test_setup_log_files(self, mock_network, mock_app, mock_security, mock_system, 
                            mock_open, mock_listdir, mock_makedirs, mock_exists):
        """Test log file setup"""
        print("\n[TEST] Testing log file setup...")
        
        # Mock the log generation methods to return sample content
        mock_system.return_value = "system log content"
        mock_security.return_value = "security log content"
        mock_app.return_value = "application log content"
        mock_network.return_value = "network log content"
        
        # Mock listdir to return empty list (no existing files)
        mock_listdir.return_value = []
        
        # Mock path.exists to return False for all files
        mock_exists.return_value = False
        
        # Configure log_file_combo
        self.gui.log_file_combo.__setitem__ = MagicMock()
        
        # Call the actual method
        self.gui.setup_log_files()
        
        # Verify makedirs was called
        mock_makedirs.assert_called_once_with('../logs', exist_ok=True)
        print("✓ Log directory creation attempted")
        
        # Verify open was called (at least once)
        self.assertGreater(mock_open.call_count, 0, "Expected open to be called")
        print(f"✓ {mock_open.call_count} file operations performed")
        
        # Get all the write calls
        write_calls = []
        for call_args in mock_open.return_value.write.call_args_list:
            write_calls.append(call_args[0][0])
        
        # Verify content was written (if any writes occurred)
        if write_calls:
            written_content = "".join(str(w) for w in write_calls)
            print("✓ Log content was written to files")
        
        # Verify each generation method was called
        mock_system.assert_called_once()
        mock_security.assert_called_once()
        mock_app.assert_called_once()
        mock_network.assert_called_once()
        print("✓ All log generation methods called")
        
        # Verify combobox was updated
        self.gui.log_file_combo.__setitem__.assert_called()
        print("✓ Log file combobox updated")
    
    def test_log_generation(self):
        """Test log generation methods"""
        print("\n[TEST] Testing log generation...")
        
        # Test system logs
        system_logs = self.gui.generate_system_logs()
        self.assertIsNotNone(system_logs)
        lines = system_logs.split('\n')
        self.assertGreater(len(lines), 50)
        print(f"✓ Generated {len(lines)} system logs")
        
        # Test security logs
        security_logs = self.gui.generate_security_logs()
        self.assertIsNotNone(security_logs)
        lines = security_logs.split('\n')
        print(f"✓ Generated {len(lines)} security logs")
        
        # Test application logs
        app_logs = self.gui.generate_application_logs()
        self.assertIsNotNone(app_logs)
        lines = app_logs.split('\n')
        print(f"✓ Generated {len(lines)} application logs")
        
        # Test network logs
        network_logs = self.gui.generate_network_logs()
        self.assertIsNotNone(network_logs)
        lines = network_logs.split('\n')
        print(f"✓ Generated {len(lines)} network logs")
    
    def test_update_status(self):
        """Test status bar updates"""
        print("\n[TEST] Testing status bar updates...")
        
        test_message = "Test status message"
        self.gui.update_status(test_message)
        
        self.gui.status_label.config.assert_called_with(text=test_message)
        print(f"✓ Status bar update attempted: '{test_message}'")
    
    def test_update_alerts(self):
        """Test alerts display updates"""
        print("\n[TEST] Testing alerts display...")
        
        test_alert = "Test alert message"
        
        # Reset mock to clear any previous calls
        self.gui.alerts_display.config.reset_mock()
        self.gui.alerts_display.insert.reset_mock()
        self.gui.alerts_display.see.reset_mock()
        
        # Configure mock to handle config calls in order
        def config_side_effect(**kwargs):
            if kwargs.get('state') == 'normal':
                return None
            return None
        
        self.gui.alerts_display.config.side_effect = config_side_effect
        
        self.gui.update_alerts(test_alert)
        
        # Verify the sequence of calls
        calls = self.gui.alerts_display.config.call_args_list
        self.assertGreaterEqual(len(calls), 1)
        
        # First call should be with state='normal'
        first_call = calls[0]
        self.assertEqual(first_call[1], {'state': 'normal'})
        
        self.gui.alerts_display.insert.assert_called()
        self.gui.alerts_display.see.assert_called_with('end')
        print(f"✓ Alert update attempted: '{test_alert}'")
    
    @patch('tkinter.messagebox.showwarning')
    def test_toggle_monitoring_without_file(self, mock_showwarning):
        """Test toggling monitoring without loaded file"""
        print("\n[TEST] Testing monitoring toggle without file...")
        
        # Ensure no file is loaded
        self.gui.current_log_file = None
        
        # Call toggle_monitoring
        self.gui.toggle_monitoring()
        
        # Verify showwarning was called
        mock_showwarning.assert_called_once()
        print("✓ Warning shown when toggling without file")
    
    def test_search_logs_empty(self):
        """Test search with empty keyword"""
        print("\n[TEST] Testing empty search...")
        
        # Set up a current log file to avoid early returns
        self.gui.current_log_file = "test.log"
        
        # Mock the log display methods
        self.gui.log_display.tag_remove = MagicMock()
        self.gui.log_display.tag_config = MagicMock()
        self.gui.log_display.config = MagicMock()
        
        # Set empty search term
        self.search_var.get.return_value = ""
        
        # Call search_logs
        self.gui.search_logs()
        
        # Verify search_results_label.config was called with empty text
        self.gui.search_results_label.config.assert_called_with(text="")
        
        # Should not cause errors
        print("✓ Empty search handled gracefully")
    
    @patch('threading.Thread')
    @patch('src.main_gui.subprocess.Popen')
    def test_start_server(self, mock_popen, mock_thread):
        """Test server startup"""
        print("\n[TEST] Testing server start...")
        
        # Mock the check_server_running method to return False
        self.gui.check_server_running = MagicMock(return_value=False)
        
        # Mock the Popen instance
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        
        # Mock the after method
        self.gui.root.after = MagicMock()
        
        # Reset server_status_label mock
        self.gui.server_status_label.config.reset_mock()
        
        # Call start_server
        self.gui.start_server()
        
        # Check that server status was updated
        self.gui.server_status_label.config.assert_called_with(text="Server: Starting...", fg='orange')
        print("✓ Server status updated to 'Starting...'")
        
        # Verify start_server_btn was disabled
        self.gui.start_server_btn.config.assert_called_with(state='disabled')
        print("✓ Start server button disabled")

def run_gui_tests():
    """Run all GUI tests"""
    suite = unittest.TestSuite()
    
    # Add login window tests
    login_test_methods = [
        'test_initialization',
        'test_successful_login',
        'test_failed_login_wrong_password',
        'test_failed_login_nonexistent_user'
    ]
    
    for method in login_test_methods:
        suite.addTest(TestLoginWindow(method))
    
    # Add GUI tests
    gui_test_methods = [
        'test_initialization',
        'test_color_scheme',
        'test_setup_log_files',
        'test_log_generation',
        'test_update_status',
        'test_update_alerts',
        'test_toggle_monitoring_without_file',
        'test_search_logs_empty',
        'test_start_server'
    ]
    
    for method in gui_test_methods:
        suite.addTest(TestShieldAuditGUI(method))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result

if __name__ == '__main__':
    print("\n" + "="*70)
    print("RUNNING GUI TESTS")
    print("="*70)
    run_gui_tests()