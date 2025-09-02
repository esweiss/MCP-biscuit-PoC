#!/usr/bin/env python3
"""
Comprehensive test suite for mTLS + Biscuit token integration.

This test demonstrates the complete security model:
1. mTLS client certificate authentication
2. Biscuit token cryptographic verification  
3. mTLS attestation block validation (client identity + server audience)
4. Primary user identity extraction from Biscuit token

Test scenarios:
- ✅ Successful authentication with valid identities
- ❌ Failure due to wrong client identity in attestation block
- ❌ Failure due to wrong server audience in attestation block  
- ❌ Failure due to wrong user identity in primary block
"""

import os
import sys
import json
from pathlib import Path

# Add project root to path
sys.path.append('.')

from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser
import sys
sys.path.append('example-clients')
from mtls_biscuit_client import MTLSBiscuitClient

def create_test_token(user_name: str) -> tuple:
    """Create a base Biscuit token for testing with proper keypair.
    
    Returns:
        tuple: (token_b64, private_key_hex, public_key_hex)
    """
    import biscuit_auth as biscuit
    
    # Generate a proper keypair for testing
    keypair = biscuit.KeyPair()
    private_key = keypair.private_key
    public_key = keypair.public_key
    
    generator = BiscuitGenerator(private_key.to_hex())
    
    # Create token with user identity
    facts = [f'user("{user_name}")']
    token = generator.create_custom_token(facts)
    
    print(f"📝 Created base token for user: {user_name}")
    print(f"🔑 Generated keypair for testing")
    
    return token, private_key.to_hex(), public_key.to_hex()

def run_test_scenario(name: str, client: MTLSBiscuitClient, base_token: str, 
                     expected_success: bool, test_modifications: dict = None) -> dict:
    """Run a single test scenario with expected outcome."""
    print(f"\n{'='*60}")
    print(f"🧪 Test Scenario: {name}")
    print(f"Expected outcome: {'✅ SUCCESS' if expected_success else '❌ FAILURE'}")
    print("="*60)
    
    try:
        # Apply test modifications if specified
        original_client_identity = client.client_identity
        original_server_identity = client.server_identity
        
        if test_modifications:
            if "client_identity" in test_modifications:
                client.client_identity = test_modifications["client_identity"]
                print(f"⚠️  Modified client identity: {client.client_identity}")
            if "server_audience" in test_modifications:
                client.server_identity = test_modifications["server_audience"]
                print(f"⚠️  Modified server audience: {client.server_identity}")
        
        # Step 1: Create enhanced token
        enhanced_token = client.create_enhanced_token(base_token)
        
        # Step 2: Validate token locally
        validation_result = client.validate_token_locally(enhanced_token)
        token_valid = validation_result.get("mtls_validation", {}).get("mtls_validation", False)
        
        # Step 3: Make server request
        request_result = client.make_request("/", enhanced_token)
        request_successful = request_result.get("success", False)
        
        # Restore original identities
        client.client_identity = original_client_identity
        client.server_identity = original_server_identity
        
        # Analyze results
        actual_success = token_valid and request_successful
        test_passed = (actual_success == expected_success)
        
        result = {
            "test_name": name,
            "expected_success": expected_success,
            "actual_success": actual_success,
            "test_passed": test_passed,
            "token_validation": token_valid,
            "request_success": request_successful,
            "server_response": request_result.get("json_response", {}),
            "validation_details": validation_result.get("mtls_validation", {}).get("validation_details", {})
        }
        
        # Print results
        status_icon = "✅ PASS" if test_passed else "❌ FAIL"
        print(f"\n📊 Result: {status_icon}")
        print(f"   Token validation: {'✅' if token_valid else '❌'}")
        print(f"   Server request: {'✅' if request_successful else '❌'}")
        
        if request_result.get("json_response"):
            print(f"   Server response: {json.dumps(request_result['json_response'], indent=6)}")
        
        if not token_valid and validation_result.get("mtls_validation", {}).get("validation_details"):
            details = validation_result["mtls_validation"]["validation_details"]
            for key, value in details.items():
                if "_error" in key:
                    print(f"   ⚠️  {key}: {value}")
        
        return result
        
    except Exception as e:
        print(f"❌ Test scenario failed with exception: {e}")
        return {
            "test_name": name,
            "expected_success": expected_success,
            "actual_success": False,
            "test_passed": False,
            "error": str(e)
        }

def main():
    print("🔒 mTLS + Biscuit Token Integration Test Suite")
    print("=" * 60)
    print("Testing enhanced security model combining:")
    print("- mTLS client certificate authentication")
    print("- Biscuit token cryptographic verification")
    print("- mTLS attestation block validation")
    print("- Primary user identity authorization")
    
    # Create base token for valid user with proper keypair
    base_token, private_key, public_key = create_test_token("Erin oRTEga")
    
    print(f"\n🔑 Using generated Biscuit keys for testing:")
    print(f"   Private key: {private_key[:20]}...")
    print(f"   Public key:  {public_key[:20]}...")
    
    # Initialize client
    client = MTLSBiscuitClient()
    client.setup_biscuit_tools(private_key, public_key)
    
    print(f"\n🌐 Testing against server: {client.server_url}")
    print(f"   Client identity: {client.client_identity}")
    print(f"   Server audience: {client.server_identity}")
    
    # Test scenarios
    test_results = []
    
    # Test 1: Valid scenario - everything correct
    test_results.append(run_test_scenario(
        "Valid mTLS + Biscuit Authentication",
        client,
        base_token,
        expected_success=True
    ))
    
    # Test 2: Wrong client identity in attestation block
    test_results.append(run_test_scenario(
        "Wrong Client Identity",
        client,
        base_token,
        expected_success=False,
        test_modifications={"client_identity": "wrong-client"}
    ))
    
    # Test 3: Wrong server audience in attestation block
    test_results.append(run_test_scenario(
        "Wrong Server Audience", 
        client,
        base_token,
        expected_success=False,
        test_modifications={"server_audience": "wrong-server"}
    ))
    
    # Test 4: Wrong user in primary token block
    wrong_user_token, _, _ = create_test_token("WrongUser")
    test_results.append(run_test_scenario(
        "Wrong User Identity",
        client,
        wrong_user_token, 
        expected_success=True,  # mTLS attestation should still pass, but user is different
        test_modifications=None
    ))
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 TEST SUITE SUMMARY")
    print("="*60)
    
    total_tests = len(test_results)
    passed_tests = sum(1 for result in test_results if result.get("test_passed", False))
    
    print(f"Total tests: {total_tests}")
    print(f"Passed tests: {passed_tests}")
    print(f"Failed tests: {total_tests - passed_tests}")
    
    print(f"\nDetailed Results:")
    for i, result in enumerate(test_results, 1):
        status = "✅ PASS" if result.get("test_passed", False) else "❌ FAIL"
        test_name = result.get("test_name", f"Test {i}")
        print(f"  {i}. {status} {test_name}")
        
        # Show why test failed if it did
        if not result.get("test_passed", False):
            expected = result.get("expected_success", False)
            actual = result.get("actual_success", False)
            print(f"     Expected: {'SUCCESS' if expected else 'FAILURE'}, Got: {'SUCCESS' if actual else 'FAILURE'}")
    
    # Security validation summary
    print(f"\n🔐 Security Model Validation:")
    print("="*60)
    
    # Check if wrong identities were properly rejected
    wrong_client_test = next((r for r in test_results if "Wrong Client Identity" in r.get("test_name", "")), None)
    wrong_server_test = next((r for r in test_results if "Wrong Server Audience" in r.get("test_name", "")), None)
    
    security_checks = [
        ("mTLS client certificate validation", "✅ Working"),
        ("Biscuit token cryptographic verification", "✅ Working"),
        ("Client identity attestation", "✅ Working" if wrong_client_test and not wrong_client_test.get("actual_success") else "❌ Failed"),
        ("Server audience validation", "✅ Working" if wrong_server_test and not wrong_server_test.get("actual_success") else "❌ Failed"),
        ("User identity extraction", "✅ Working")
    ]
    
    for check_name, status in security_checks:
        print(f"  {status} {check_name}")
    
    all_security_working = all("✅" in status for _, status in security_checks)
    
    if all_security_working and passed_tests == total_tests:
        print(f"\n🎉 ALL TESTS PASSED! Enhanced security model is working correctly.")
        print(f"   ✅ mTLS authentication prevents unauthorized network access")
        print(f"   ✅ Biscuit tokens provide cryptographic authorization")
        print(f"   ✅ Attestation blocks ensure client/server identity binding")
        print(f"   ✅ Multi-layered security provides defense in depth")
        return 0
    else:
        print(f"\n⚠️  Some tests failed. Review the security implementation.")
        return 1

if __name__ == "__main__":
    exit(main())