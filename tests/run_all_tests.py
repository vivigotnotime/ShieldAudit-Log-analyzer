#!/usr/bin/env python3
"""
Main test runner for ShieldAudit
Runs all unit tests and displays comprehensive results
"""
import unittest
import sys
import os
import time
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*80)
    print(f" {text}")
    print("="*80)

def print_results(result, test_name):
    """Print detailed test results"""
    print(f"\n📊 {test_name} RESULTS:")
    print("-" * 40)
    print(f"✅ Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"❌ Failed: {len(result.failures)}")
    print(f"⚠️  Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ FAILURES:")
        for i, (test, traceback) in enumerate(result.failures, 1):
            print(f"  {i}. {test}")
            print(f"     {traceback.split(chr(10))[-2] if chr(10) in traceback else traceback[:100]}...")
    
    if result.errors:
        print("\n⚠️ ERRORS:")
        for i, (test, traceback) in enumerate(result.errors, 1):
            print(f"  {i}. {test}")
            print(f"     {traceback.split(chr(10))[-2] if chr(10) in traceback else traceback[:100]}...")

def run_all_tests():
    """Run all test suites"""
    start_time = time.time()
    
    print_header("🔒 SHIELDAUDIT TEST SUITE")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    
    # Import test modules
    from test_security_utils import run_security_tests
    from test_server_vault import run_server_tests
    from test_main_gui import run_gui_tests
    from test_integration import run_integration_tests
    
    results = {}
    
    # Run security utils tests
    print_header("🔧 TESTING SECURITY UTILITIES")
    results['security'] = run_security_tests()
    
    # Run server tests
    print_header("🖥️ TESTING SERVER")
    results['server'] = run_server_tests()
    
    # Run GUI tests (skip if no display)
    print_header("🎨 TESTING GUI")
    if 'DISPLAY' not in os.environ and sys.platform != 'win32':
        print("⚠️ Skipping GUI tests (no display available)")
        results['gui'] = None
    else:
        results['gui'] = run_gui_tests()
    
    # Run integration tests
    print_header("🔗 TESTING INTEGRATION")
    results['integration'] = run_integration_tests()
    
    # Print summary
    elapsed_time = time.time() - start_time
    
    print_header("📈 FINAL TEST SUMMARY")
    
    total_tests = 0
    total_passed = 0
    total_failed = 0
    total_errors = 0
    
    for test_type, result in results.items():
        if result:
            tests = result.testsRun
            passed = tests - len(result.failures) - len(result.errors)
            failed = len(result.failures)
            errors = len(result.errors)
            
            total_tests += tests
            total_passed += passed
            total_failed += failed
            total_errors += errors
            
            status = "✅" if failed == 0 and errors == 0 else "⚠️"
            print(f"\n{status} {test_type.upper()}:")
            print(f"   Tests: {tests}")
            print(f"   Passed: {passed}")
            print(f"   Failed: {failed}")
            print(f"   Errors: {errors}")
    
    print("\n" + "-" * 40)
    print(f"⏱️  Total time: {elapsed_time:.2f} seconds")
    print(f"📊 TOTAL TESTS: {total_tests}")
    print(f"✅ TOTAL PASSED: {total_passed}")
    
    if total_failed > 0:
        print(f"❌ TOTAL FAILED: {total_failed}")
    if total_errors > 0:
        print(f"⚠️ TOTAL ERRORS: {total_errors}")
    
    if total_failed == 0 and total_errors == 0:
        print("\n🎉 ALL TESTS PASSED!")
    else:
        print(f"\n❌ {total_failed + total_errors} TEST(S) FAILED")
    
    return total_failed == 0 and total_errors == 0

def run_specific_test(test_module, test_class=None, test_method=None):
    """Run a specific test"""
    print_header(f"🔍 RUNNING SPECIFIC TEST")
    
    if test_module == 'security':
        from test_security_utils import TestLogNode, TestCircularLogBuffer, TestSecurityUtils
        
        if test_class == 'LogNode':
            suite = unittest.TestLoader().loadTestsFromTestCase(TestLogNode)
        elif test_class == 'CircularLogBuffer':
            suite = unittest.TestLoader().loadTestsFromTestCase(TestCircularLogBuffer)
        elif test_class == 'SecurityUtils':
            suite = unittest.TestLoader().loadTestsFromTestCase(TestSecurityUtils)
        else:
            import test_security_utils
            suite = unittest.TestLoader().loadTestsFromModule(test_security_utils)
    
    elif test_module == 'server':
        from test_server_vault import TestShieldAuditServer
        
        if test_method:
            suite = unittest.TestSuite()
            suite.addTest(TestShieldAuditServer(test_method))
        else:
            suite = unittest.TestLoader().loadTestsFromTestCase(TestShieldAuditServer)
    
    elif test_module == 'gui':
        from test_main_gui import TestLoginWindow, TestShieldAuditGUI
        
        if test_class == 'LoginWindow':
            suite = unittest.TestLoader().loadTestsFromTestCase(TestLoginWindow)
        elif test_class == 'ShieldAuditGUI':
            suite = unittest.TestLoader().loadTestsFromTestCase(TestShieldAuditGUI)
        else:
            print("Available GUI test classes: LoginWindow, ShieldAuditGUI")
            return False
    
    elif test_module == 'integration':
        from test_integration import TestShieldAuditIntegration
        
        if test_method:
            suite = unittest.TestSuite()
            suite.addTest(TestShieldAuditIntegration(test_method))
        else:
            suite = unittest.TestLoader().loadTestsFromTestCase(TestShieldAuditIntegration)
    
    else:
        print(f"Unknown test module: {test_module}")
        print("Available modules: security, server, gui, integration")
        return False
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return len(result.failures) == 0 and len(result.errors) == 0

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Run ShieldAudit tests')
    parser.add_argument('--module', '-m', help='Specific module to test (security, server, gui, integration)')
    parser.add_argument('--class', '-c', dest='test_class', help='Specific test class')
    parser.add_argument('--test', '-t', help='Specific test method')
    
    args = parser.parse_args()
    
    if args.module:
        success = run_specific_test(args.module, args.test_class, args.test)
        sys.exit(0 if success else 1)
    else:
        success = run_all_tests()
        sys.exit(0 if success else 1)