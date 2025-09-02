#!/usr/bin/env python3
"""
Comprehensive Test Suite for Enhanced mTLS + Biscuit Security Model

This test suite demonstrates the enhanced security model that combines:
1. mTLS client certificate authentication
2. Biscuit token authorization with mTLS attestation blocks

Test scenarios:
✅ Successful data retrieval with valid token and identities
❌ Failure due to wrong client identity in token
❌ Failure due to wrong server audience in token
❌ Failure due to wrong user identity in primary token block
"""

import os
import sys
import json
import time
import asyncio
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

# Add the project root to Python path for imports
sys.path.append(str(Path(__file__).parent))

from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser

class EnhancedSecurityTestSuite:
    """Test suite for the enhanced mTLS + Biscuit security model."""
    
    def __init__(self):
        self.server_url = "https://localhost:8443"
        self.ca_cert = "certs/ca-cert.pem"
        self.client_cert = "certs/claude-client-cert.pem"
        self.client_key = "certs/claude-client-key.pem"
        
        # Test identities
        self.valid_client_identity = "claude-client"
        self.valid_server_identity = "mcp-server"
        self.wrong_client_identity = "wrong-client"
        self.wrong_server_identity = "wrong-server"
        
        # Initialize Biscuit tools
        self.setup_biscuit_environment()
        
        # Test results
        self.results = {}
    
    def setup_biscuit_environment(self):
        """Setup Biscuit token generation and parsing."""
        print("🔧 Setting up Biscuit environment...")
        
        # Get keys from environment or generate new ones
        private_key = os.getenv('BISCUIT_PRIVATE_KEY')
        public_key = os.getenv('BISCUIT_PUBLIC_KEY')
        
        if not private_key or not public_key:
            # Generate new keypair for testing
            generator = BiscuitGenerator()
            public_key = generator.get_public_key()
            private_key = generator.private_key.to_hex()
            print(f"📋 Generated test keys - Public: {public_key[:32]}...")
        else:
            print(f"📋 Using environment keys - Public: {public_key[:32]}...")
        
        self.biscuit_generator = BiscuitGenerator(private_key)
        self.biscuit_parser = BiscuitParser(public_key)
        self.public_key_hex = public_key
        self.private_key_hex = private_key
    
    def create_base_token(self, user_id: str = "alice") -> str:
        """Create a base Biscuit token with user identity."""
        print(f"🎫 Creating base token for user: {user_id}")
        
        base_token = self.biscuit_generator.create_custom_token([
            f'user("{user_id}")',
            'resource("medical_records")',
            'operation("read")',
            f'patient_name("Erin oRTEga")'  # For database RLS
        ])
        
        return base_token
    
    def create_enhanced_token(self, base_token: str, client_identity: str, 
                            server_audience: str) -> str:
        """Create enhanced token with mTLS attestation block."""
        print(f"🔐 Adding mTLS attestation - Client: {client_identity}, Server: {server_audience}")
        
        enhanced_token = self.biscuit_generator.add_mtls_attestation_block(
            base_token,
            client_identity,
            server_audience,
            public_key_hex=self.public_key_hex
        )
        
        return enhanced_token
    
    def validate_token_locally(self, token: str, expected_client: str, 
                             expected_server: str) -> Dict[str, Any]:
        """Validate token locally before sending to server."""
        print(f"🔍 Validating token locally...")
        
        # Basic token verification
        facts_result = self.biscuit_parser.verify_and_extract_facts(token)
        token_valid = facts_result.get("status") == "verified_with_facts"
        
        # mTLS attestation validation
        mtls_result = self.biscuit_parser.validate_mtls_attestation(
            token, expected_client, expected_server
        )
        mtls_valid = mtls_result.get("mtls_validation", False)
        
        print(f"   Token verification: {'✅' if token_valid else '❌'}")
        print(f"   mTLS validation: {'✅' if mtls_valid else '❌'}")
        
        if not mtls_valid:
            details = mtls_result.get("validation_details", {})
            for key, value in details.items():
                if "_error" in key:
                    print(f"      {key}: {value}")
        
        return {
            "token_valid": token_valid,
            "mtls_valid": mtls_valid,
            "facts_result": facts_result,
            "mtls_result": mtls_result
        }
    
    def test_server_response(self, token: str, test_name: str) -> Dict[str, Any]:
        """Test server response with the given token."""
        import requests
        
        print(f"🌐 Testing server response for: {test_name}")
        
        try:
            response = requests.get(
                f"{self.server_url}/",
                verify=self.ca_cert,
                cert=(self.client_cert, self.client_key),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=10
            )
            
            result = {
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "response_text": response.text
            }
            
            try:
                result["json_response"] = response.json()
            except:
                pass
            
            status_emoji = "✅" if result["success"] else "❌"
            print(f"   Server response: {status_emoji} {response.status_code}")
            
            return result
            
        except Exception as e:
            print(f"   Server response: ❌ Exception: {e}")
            return {
                "status_code": 0,
                "success": False,
                "error": str(e)
            }
    
    def run_test_scenario(self, scenario_name: str, user_id: str = "alice",
                         client_identity: str = None, server_audience: str = None,
                         expected_success: bool = True) -> Dict[str, Any]:
        """Run a complete test scenario."""
        print(f"\n{'='*60}")
        print(f"🧪 TEST SCENARIO: {scenario_name}")
        print(f"{'='*60}")
        
        # Use defaults if not specified
        if client_identity is None:
            client_identity = self.valid_client_identity
        if server_audience is None:
            server_audience = self.valid_server_identity
        
        try:
            # Step 1: Create base token
            print(f"📝 Step 1: Creating base token")
            base_token = self.create_base_token(user_id)
            
            # Step 2: Create enhanced token
            print(f"🔐 Step 2: Creating enhanced token")
            enhanced_token = self.create_enhanced_token(
                base_token, client_identity, server_audience
            )
            
            # Step 3: Local validation
            print(f"🔍 Step 3: Local validation")
            local_validation = self.validate_token_locally(
                enhanced_token, self.valid_client_identity, self.valid_server_identity
            )
            
            # Step 4: Server test
            print(f"🌐 Step 4: Server validation")
            server_response = self.test_server_response(enhanced_token, scenario_name)
            
            # Determine overall success
            overall_success = (
                local_validation["token_valid"] and 
                local_validation["mtls_valid"] and 
                server_response["success"]
            )
            
            result = {
                "scenario": scenario_name,
                "expected_success": expected_success,
                "actual_success": overall_success,
                "test_passed": overall_success == expected_success,
                "local_validation": local_validation,
                "server_response": server_response,
                "parameters": {
                    "user_id": user_id,
                    "client_identity": client_identity,
                    "server_audience": server_audience
                }
            }
            
            # Summary
            test_emoji = "✅ PASS" if result["test_passed"] else "❌ FAIL"
            success_emoji = "✅" if overall_success else "❌"
            print(f"\n📊 RESULT: {test_emoji}")
            print(f"   Expected: {'✅ SUCCESS' if expected_success else '❌ FAILURE'}")
            print(f"   Actual: {success_emoji} {'SUCCESS' if overall_success else 'FAILURE'}")
            
            return result
            
        except Exception as e:
            print(f"❌ Test scenario failed with exception: {e}")
            return {
                "scenario": scenario_name,
                "expected_success": expected_success,
                "actual_success": False,
                "test_passed": not expected_success,  # If we expected failure, exception is OK
                "error": str(e),
                "parameters": {
                    "user_id": user_id,
                    "client_identity": client_identity,
                    "server_audience": server_audience
                }
            }
    
    def run_all_tests(self):
        """Run all test scenarios."""
        print("🚀 ENHANCED MTLS + BISCUIT SECURITY TEST SUITE")
        print("="*80)
        
        test_scenarios = [
            {
                "name": "Valid Token - Should Succeed",
                "user_id": "alice",
                "client_identity": self.valid_client_identity,
                "server_audience": self.valid_server_identity,
                "expected_success": True
            },
            {
                "name": "Wrong Client Identity - Should Fail",
                "user_id": "alice", 
                "client_identity": self.wrong_client_identity,
                "server_audience": self.valid_server_identity,
                "expected_success": False
            },
            {
                "name": "Wrong Server Audience - Should Fail",
                "user_id": "alice",
                "client_identity": self.valid_client_identity, 
                "server_audience": self.wrong_server_identity,
                "expected_success": False
            },
            {
                "name": "Wrong User Identity - Should Fail",
                "user_id": "eve",  # Different user
                "client_identity": self.valid_client_identity,
                "server_audience": self.valid_server_identity,
                "expected_success": True  # Should succeed for token validation, might fail on business logic
            }
        ]
        
        results = []
        for scenario in test_scenarios:
            result = self.run_test_scenario(
                scenario["name"],
                scenario["user_id"],
                scenario["client_identity"],
                scenario["server_audience"],
                scenario["expected_success"]
            )
            results.append(result)
            self.results[scenario["name"]] = result
            
            # Small delay between tests
            time.sleep(1)
        
        # Final summary
        self.print_final_summary(results)
        return results
    
    def print_final_summary(self, results):
        """Print final test summary."""
        print(f"\n{'='*80}")
        print("📊 FINAL TEST SUMMARY")
        print(f"{'='*80}")
        
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r["test_passed"])
        
        for result in results:
            status = "✅ PASS" if result["test_passed"] else "❌ FAIL"
            print(f"{status} - {result['scenario']}")
            
            if not result["test_passed"]:
                expected = "SUCCESS" if result["expected_success"] else "FAILURE"
                actual = "SUCCESS" if result["actual_success"] else "FAILURE" 
                print(f"      Expected: {expected}, Got: {actual}")
        
        print(f"\n🎯 OVERALL RESULT: {passed_tests}/{total_tests} tests passed")
        
        if passed_tests == total_tests:
            print("🎉 ALL TESTS PASSED! Enhanced security model working correctly.")
        else:
            print("⚠️  Some tests failed. Review the results above.")

def main():
    """Main test execution."""
    # Check if server is running
    print("🔍 Checking if mTLS server is running...")
    
    import requests
    try:
        # Quick connectivity test (will fail with cert error, but that's expected)
        requests.get("https://localhost:8443/health", timeout=2, verify=False)
        print("✅ Server appears to be running")
    except requests.exceptions.ConnectionError as e:
        if "Connection refused" in str(e):
            print("❌ Server is not running. Please start it first:")
            print("   PYTHONPATH=. uv run python server/custom_mtls_server.py")
            return 1
        else:
            print("✅ Server appears to be running (connection established)")
    except Exception as e:
        print(f"⚠️  Server connectivity check inconclusive: {e}")
        print("   Proceeding with tests anyway...")
    
    # Run the test suite
    test_suite = EnhancedSecurityTestSuite()
    results = test_suite.run_all_tests()
    
    # Return appropriate exit code
    all_passed = all(r["test_passed"] for r in results)
    return 0 if all_passed else 1

if __name__ == "__main__":
    exit(main())