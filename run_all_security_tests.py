#!/usr/bin/env python3
"""
Comprehensive Security Test Runner

This script runs all the enhanced mTLS + Biscuit security tests and provides
a comprehensive summary of the security model validation.

Tests included:
✅ Enhanced security demonstration (successful case)
❌ Wrong client identity rejection test
❌ Wrong server audience rejection test  
👤 Wrong user identity handling test
📊 Data retrieval test

Usage:
    python run_all_security_tests.py
"""

import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

class SecurityTestRunner:
    """Runner for all security test scenarios."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_results = {}
        
        # Test definitions
        self.tests = [
            {
                "name": "Enhanced Security Demo",
                "script": "demo_enhanced_security.py",
                "description": "Demonstrates successful enhanced security flow",
                "expected_result": "success",
                "category": "positive"
            },
            {
                "name": "Data Retrieval Test", 
                "script": "test_data_retrieval.py",
                "description": "Tests secure data access with enhanced tokens",
                "expected_result": "success",
                "category": "positive"
            },
            {
                "name": "Wrong Client Identity",
                "script": "test_wrong_client_identity.py", 
                "description": "Tests rejection of tokens with wrong client identity",
                "expected_result": "success_rejection",
                "category": "negative"
            },
            {
                "name": "Wrong Server Audience",
                "script": "test_wrong_audience.py",
                "description": "Tests rejection of tokens with wrong server audience", 
                "expected_result": "success_rejection",
                "category": "negative"
            },
            {
                "name": "Wrong User Identity",
                "script": "test_wrong_user_identity.py",
                "description": "Tests handling of tokens with unauthorized user",
                "expected_result": "handled_properly",
                "category": "business_logic"
            },
            {
                "name": "Comprehensive Test Suite",
                "script": "test_enhanced_mtls_biscuit.py",
                "description": "Comprehensive automated test suite",
                "expected_result": "success",
                "category": "comprehensive"
            }
        ]
    
    def check_server_status(self) -> bool:
        """Check if the mTLS server is running."""
        import requests
        
        try:
            response = requests.get("https://localhost:8443/health", timeout=3, verify=False)
            return True
        except requests.exceptions.ConnectionError as e:
            if "Connection refused" in str(e):
                return False
            else:
                return True  # Server is running but rejected connection (expected)
        except Exception:
            return False
    
    def run_test(self, test_info: Dict) -> Dict:
        """Run a single test and return results."""
        print(f"\n{'='*80}")
        print(f"🧪 RUNNING: {test_info['name']}")
        print(f"{'='*80}")
        print(f"📝 Description: {test_info['description']}")
        print(f"📂 Script: {test_info['script']}")
        print(f"🎯 Expected: {test_info['expected_result']}")
        
        script_path = self.project_root / test_info['script']
        
        if not script_path.exists():
            return {
                "name": test_info['name'],
                "status": "error",
                "message": f"Test script not found: {script_path}",
                "exit_code": -1
            }
        
        try:
            # Run the test
            start_time = time.time()
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=60  # 60 second timeout per test
            )
            duration = time.time() - start_time
            
            # Determine test status
            if result.returncode == 0:
                status = "passed"
                status_emoji = "✅"
            else:
                status = "failed"
                status_emoji = "❌"
            
            print(f"\n{status_emoji} TEST RESULT: {status.upper()}")
            print(f"⏱️  Duration: {duration:.2f} seconds")
            print(f"🔢 Exit code: {result.returncode}")
            
            # Show output if verbose or if test failed
            if result.stdout:
                print(f"\n📄 Output:")
                print("-" * 40)
                print(result.stdout)
            
            if result.stderr:
                print(f"\n⚠️  Errors:")
                print("-" * 40)
                print(result.stderr)
            
            return {
                "name": test_info['name'],
                "script": test_info['script'],
                "status": status,
                "exit_code": result.returncode,
                "duration": duration,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "category": test_info['category'],
                "expected_result": test_info['expected_result']
            }
            
        except subprocess.TimeoutExpired:
            print("⏰ TEST TIMEOUT: Test exceeded 60 seconds")
            return {
                "name": test_info['name'],
                "status": "timeout",
                "message": "Test exceeded timeout limit",
                "exit_code": -1
            }
        except Exception as e:
            print(f"❌ TEST ERROR: {e}")
            return {
                "name": test_info['name'],
                "status": "error", 
                "message": str(e),
                "exit_code": -1
            }
    
    def run_all_tests(self) -> List[Dict]:
        """Run all security tests."""
        print("🚀 ENHANCED MTLS + BISCUIT SECURITY TEST SUITE")
        print("="*80)
        print(f"🗓️  Test run started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📁 Project root: {self.project_root}")
        print(f"🧪 Total tests: {len(self.tests)}")
        
        # Check server status
        print(f"\n🔍 Checking server status...")
        if self.check_server_status():
            print("✅ mTLS server is running")
        else:
            print("❌ mTLS server is not running!")
            print("⚠️  Some tests may fail. Start server with:")
            print("   PYTHONPATH=. uv run python server/custom_mtls_server.py")
            
            # Ask user if they want to continue
            try:
                response = input("\nContinue with tests anyway? (y/N): ").lower()
                if response not in ['y', 'yes']:
                    print("Aborting test run.")
                    return []
            except KeyboardInterrupt:
                print("\nTest run cancelled by user.")
                return []
        
        results = []
        
        for i, test_info in enumerate(self.tests, 1):
            print(f"\n🎯 Test {i}/{len(self.tests)}")
            result = self.run_test(test_info)
            results.append(result)
            self.test_results[test_info['name']] = result
            
            # Small delay between tests
            if i < len(self.tests):
                time.sleep(2)
        
        return results
    
    def analyze_results(self, results: List[Dict]) -> Dict:
        """Analyze test results and provide insights."""
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r.get('status') == 'passed')
        failed_tests = sum(1 for r in results if r.get('status') == 'failed')
        error_tests = sum(1 for r in results if r.get('status') in ['error', 'timeout'])
        
        # Categorize results
        categories = {}
        for result in results:
            category = result.get('category', 'unknown')
            if category not in categories:
                categories[category] = {'passed': 0, 'failed': 0, 'error': 0}
            
            status = result.get('status', 'error')
            if status == 'passed':
                categories[category]['passed'] += 1
            elif status == 'failed':
                categories[category]['failed'] += 1
            else:
                categories[category]['error'] += 1
        
        return {
            'total': total_tests,
            'passed': passed_tests,
            'failed': failed_tests,
            'errors': error_tests,
            'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            'categories': categories
        }
    
    def print_final_summary(self, results: List[Dict], analysis: Dict):
        """Print comprehensive final summary."""
        print(f"\n{'='*80}")
        print("📊 COMPREHENSIVE TEST SUMMARY")
        print(f"{'='*80}")
        
        # Overall statistics
        print(f"🎯 OVERALL RESULTS:")
        print(f"   Total tests: {analysis['total']}")
        print(f"   Passed: {analysis['passed']} ✅")
        print(f"   Failed: {analysis['failed']} ❌") 
        print(f"   Errors: {analysis['errors']} ⚠️")
        print(f"   Success rate: {analysis['success_rate']:.1f}%")
        
        # Test categories
        print(f"\n📂 RESULTS BY CATEGORY:")
        for category, stats in analysis['categories'].items():
            total_in_cat = stats['passed'] + stats['failed'] + stats['error']
            success_rate = (stats['passed'] / total_in_cat * 100) if total_in_cat > 0 else 0
            print(f"   {category.title()}: {stats['passed']}/{total_in_cat} passed ({success_rate:.1f}%)")
        
        # Individual test results
        print(f"\n📋 INDIVIDUAL TEST RESULTS:")
        for result in results:
            status_emoji = {
                'passed': '✅',
                'failed': '❌', 
                'error': '⚠️',
                'timeout': '⏰'
            }.get(result.get('status'), '❓')
            
            duration = result.get('duration', 0)
            print(f"   {status_emoji} {result['name']} ({duration:.1f}s)")
            
            # Show failure details
            if result.get('status') != 'passed':
                if 'message' in result:
                    print(f"      💬 {result['message']}")
                elif result.get('exit_code', 0) != 0:
                    print(f"      🔢 Exit code: {result['exit_code']}")
        
        # Security model assessment
        print(f"\n🔒 SECURITY MODEL ASSESSMENT:")
        
        positive_tests = [r for r in results if r.get('category') == 'positive']
        negative_tests = [r for r in results if r.get('category') == 'negative']
        
        positive_passed = sum(1 for r in positive_tests if r.get('status') == 'passed')
        negative_passed = sum(1 for r in negative_tests if r.get('status') == 'passed')
        
        print(f"   Positive security tests: {positive_passed}/{len(positive_tests)} passed")
        print(f"   Negative security tests: {negative_passed}/{len(negative_tests)} passed")
        
        if positive_passed == len(positive_tests):
            print("   ✅ Valid requests are properly handled")
        else:
            print("   ❌ Some valid requests are being rejected")
        
        if negative_passed == len(negative_tests):
            print("   ✅ Invalid requests are properly rejected")
        else:
            print("   ❌ Some invalid requests are not being rejected")
        
        # Final verdict
        print(f"\n🎉 FINAL VERDICT:")
        if analysis['success_rate'] >= 90:
            print("   🟢 EXCELLENT: Enhanced security model working correctly")
        elif analysis['success_rate'] >= 70:
            print("   🟡 GOOD: Minor issues detected, review failed tests")
        else:
            print("   🔴 NEEDS ATTENTION: Significant issues detected")
        
        print(f"\n🗓️  Test run completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """Main test runner execution."""
    runner = SecurityTestRunner()
    
    try:
        results = runner.run_all_tests()
        
        if not results:
            print("No tests were executed.")
            return 1
        
        analysis = runner.analyze_results(results)
        runner.print_final_summary(results, analysis)
        
        # Return appropriate exit code
        return 0 if analysis['success_rate'] >= 70 else 1
        
    except KeyboardInterrupt:
        print("\n🛑 Test run interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Test runner error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())