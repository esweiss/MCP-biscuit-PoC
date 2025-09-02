#!/usr/bin/env python3
"""
Test Script: Wrong Client Identity Failure

This script demonstrates security enforcement when the client identity 
in the mTLS attestation block doesn't match the actual mTLS certificate identity.

Expected behavior: Server should reject the connection with 403 Forbidden
"""

import os
import sys
from pathlib import Path
import requests

# Add the project root to Python path for imports
sys.path.append(str(Path(__file__).parent))

from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser

def test_wrong_client_identity():
    """Test server rejection due to wrong client identity in token."""
    
    print("🔒 TESTING: Wrong Client Identity Rejection")
    print("="*60)
    
    # Setup
    generator = BiscuitGenerator()
    public_key = generator.get_public_key()
    parser = BiscuitParser(public_key)
    
    # Certificate identities  
    actual_client_identity = "claude-client"    # Real certificate CN
    wrong_client_identity = "fake-client"       # Wrong identity in token
    server_identity = "mcp-server"
    
    print(f"Actual client certificate identity: {actual_client_identity}")
    print(f"Wrong identity in token: {wrong_client_identity}")
    print(f"Server identity: {server_identity}")
    
    # Step 1: Create base token
    print(f"\n📝 Step 1: Creating base token")
    base_token = generator.create_custom_token([
        'user("alice")',
        'resource("medical_records")',
        'operation("read")'
    ])
    print("✅ Base token created")
    
    # Step 2: Create enhanced token with WRONG client identity
    print(f"\n🔐 Step 2: Creating enhanced token with wrong client identity")
    enhanced_token = generator.add_mtls_attestation_block(
        base_token,
        wrong_client_identity,  # This is wrong!
        server_identity,
        public_key_hex=public_key
    )
    print("✅ Enhanced token created (with wrong client identity)")
    
    # Step 3: Local validation (should fail)
    print(f"\n🔍 Step 3: Local validation")
    local_validation = parser.validate_mtls_attestation(
        enhanced_token,
        actual_client_identity,  # What we actually expect
        server_identity
    )
    
    local_valid = local_validation.get('mtls_validation', False)
    print(f"Local mTLS validation: {'✅ PASS' if local_valid else '❌ FAIL (expected)'}")
    
    if not local_valid:
        details = local_validation.get('validation_details', {})
        for key, value in details.items():
            if '_error' in key:
                print(f"   {key}: {value}")
    
    # Step 4: Server request (should be rejected)
    print(f"\n🌐 Step 4: Server request with wrong client identity")
    
    try:
        response = requests.get(
            "https://localhost:8443/",
            verify="certs/ca-cert.pem",
            cert=("certs/claude-client-cert.pem", "certs/claude-client-key.pem"),
            headers={
                "Authorization": f"Bearer {enhanced_token}",
                "Content-Type": "application/json"
            },
            timeout=10
        )
        
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 403:
            print("✅ SECURITY WORKING: Server correctly rejected wrong client identity (403 Forbidden)")
        elif response.status_code == 200:
            print("❌ SECURITY BREACH: Server accepted wrong client identity!")
        else:
            print(f"⚠️  Unexpected response: {response.status_code}")
        
        # Show response details
        try:
            json_response = response.json()
            error = json_response.get('error', 'No error message')
            print(f"Server message: {error}")
        except:
            print(f"Response text: {response.text}")
            
        return response.status_code == 403
        
    except Exception as e:
        print(f"❌ Request failed: {e}")
        print("Make sure the mTLS server is running:")
        print("PYTHONPATH=. uv run python server/custom_mtls_server.py")
        return False

def main():
    """Main test execution."""
    print("🔍 Checking server connectivity...")
    
    # Quick server check
    try:
        requests.get("https://localhost:8443/health", timeout=2, verify=False)
        print("✅ Server is running\n")
    except requests.exceptions.ConnectionError as e:
        if "Connection refused" in str(e):
            print("❌ Server is not running. Please start it first:")
            print("   PYTHONPATH=. uv run python server/custom_mtls_server.py")
            return 1
    
    # Run the test
    success = test_wrong_client_identity()
    
    print(f"\n📊 TEST RESULT")
    print("="*60)
    if success:
        print("✅ TEST PASSED: Server correctly rejected wrong client identity")
        print("🔒 Security enforcement working as expected")
    else:
        print("❌ TEST FAILED: Server did not properly reject wrong client identity")
        print("⚠️  Security vulnerability detected!")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())