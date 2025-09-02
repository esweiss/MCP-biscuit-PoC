#!/usr/bin/env python3
"""
Test Script: Wrong Server Audience Failure

This script demonstrates security enforcement when the server audience 
in the mTLS attestation block doesn't match the server's actual identity.

Expected behavior: Server should reject the token with 403 Forbidden
"""

import os
import sys
from pathlib import Path
import requests

# Add the project root to Python path for imports
sys.path.append(str(Path(__file__).parent))

from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser

def test_wrong_server_audience():
    """Test server rejection due to wrong server audience in token."""
    
    print("🎯 TESTING: Wrong Server Audience Rejection")
    print("="*60)
    
    # Setup
    generator = BiscuitGenerator()
    public_key = generator.get_public_key()
    parser = BiscuitParser(public_key)
    
    # Certificate identities  
    client_identity = "claude-client"           # Correct client identity
    actual_server_identity = "mcp-server"       # Real server identity
    wrong_server_audience = "wrong-server"      # Wrong audience in token
    
    print(f"Client identity: {client_identity}")
    print(f"Actual server identity: {actual_server_identity}")
    print(f"Wrong audience in token: {wrong_server_audience}")
    
    # Step 1: Create base token
    print(f"\n📝 Step 1: Creating base token")
    base_token = generator.create_custom_token([
        'user("alice")',
        'resource("medical_records")',
        'operation("read")'
    ])
    print("✅ Base token created")
    
    # Step 2: Create enhanced token with WRONG server audience
    print(f"\n🔐 Step 2: Creating enhanced token with wrong server audience")
    enhanced_token = generator.add_mtls_attestation_block(
        base_token,
        client_identity,        # This is correct
        wrong_server_audience,  # This is wrong!
        public_key_hex=public_key
    )
    print("✅ Enhanced token created (with wrong server audience)")
    
    # Step 3: Local validation (should fail)
    print(f"\n🔍 Step 3: Local validation")
    local_validation = parser.validate_mtls_attestation(
        enhanced_token,
        client_identity,
        actual_server_identity  # What the server actually expects
    )
    
    local_valid = local_validation.get('mtls_validation', False)
    print(f"Local mTLS validation: {'✅ PASS' if local_valid else '❌ FAIL (expected)'}")
    
    if not local_valid:
        details = local_validation.get('validation_details', {})
        for key, value in details.items():
            if '_error' in key:
                print(f"   {key}: {value}")
    
    # Step 4: Server request (should be rejected)
    print(f"\n🌐 Step 4: Server request with wrong server audience")
    
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
            print("✅ SECURITY WORKING: Server correctly rejected wrong audience (403 Forbidden)")
        elif response.status_code == 200:
            print("❌ SECURITY BREACH: Server accepted wrong audience!")
        else:
            print(f"⚠️  Unexpected response: {response.status_code}")
        
        # Show response details
        try:
            json_response = response.json()
            error = json_response.get('error', 'No error message')
            details = json_response.get('validation_details', {})
            print(f"Server message: {error}")
            if details:
                print(f"Validation details: {details}")
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
    success = test_wrong_server_audience()
    
    print(f"\n📊 TEST RESULT")
    print("="*60)
    if success:
        print("✅ TEST PASSED: Server correctly rejected wrong audience")
        print("🔒 Security enforcement working as expected")
    else:
        print("❌ TEST FAILED: Server did not properly reject wrong audience")
        print("⚠️  Security vulnerability detected!")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())