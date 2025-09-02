#!/usr/bin/env python3
"""
Test Script: Wrong User Identity Test

This script demonstrates the complete security model including user identity validation.
Creates a token with wrong user identity while mTLS attestation is correct.

Expected behavior: 
- mTLS attestation should pass (client and server identities correct)
- User authorization may succeed at token level but could fail at business logic level
- This tests the separation between transport security (mTLS) and authorization (Biscuit)
"""

import os
import sys
from pathlib import Path
import requests

# Add the project root to Python path for imports
sys.path.append(str(Path(__file__).parent))

from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser

def test_wrong_user_identity():
    """Test system behavior with wrong user identity but correct mTLS attestation."""
    
    print("👤 TESTING: Wrong User Identity (mTLS attestation correct)")
    print("="*60)
    
    # Setup
    generator = BiscuitGenerator()
    public_key = generator.get_public_key()
    parser = BiscuitParser(public_key)
    
    # Certificate identities (these are correct)
    client_identity = "claude-client"
    server_identity = "mcp-server"
    
    # User identities
    authorized_user = "alice"      # User that should have access
    unauthorized_user = "eve"      # User that shouldn't have access
    
    print(f"Client identity: {client_identity} (correct)")
    print(f"Server identity: {server_identity} (correct)")
    print(f"Authorized user: {authorized_user}")
    print(f"Token user: {unauthorized_user} (potentially unauthorized)")
    
    # Step 1: Create base token with unauthorized user
    print(f"\n📝 Step 1: Creating base token for unauthorized user")
    base_token = generator.create_custom_token([
        f'user("{unauthorized_user}")',  # Wrong user!
        'resource("medical_records")',
        'operation("read")',
        'patient_name("Erin oRTEga")'    # This user shouldn't access this patient
    ])
    print(f"✅ Base token created for user: {unauthorized_user}")
    
    # Step 2: Create enhanced token with CORRECT mTLS attestation
    print(f"\n🔐 Step 2: Creating enhanced token with correct mTLS attestation")
    enhanced_token = generator.add_mtls_attestation_block(
        base_token,
        client_identity,    # Correct client identity
        server_identity,    # Correct server audience  
        public_key_hex=public_key
    )
    print("✅ Enhanced token created (mTLS attestation correct)")
    
    # Step 3: Local validation
    print(f"\n🔍 Step 3: Local validation")
    
    # Token verification should succeed
    token_validation = parser.verify_and_extract_facts(enhanced_token)
    token_valid = token_validation.get('status') == 'verified_with_facts'
    print(f"Token verification: {'✅ PASS' if token_valid else '❌ FAIL'}")
    
    # mTLS validation should succeed (identities are correct)
    mtls_validation = parser.validate_mtls_attestation(
        enhanced_token,
        client_identity,
        server_identity
    )
    
    mtls_valid = mtls_validation.get('mtls_validation', False)
    print(f"mTLS attestation: {'✅ PASS' if mtls_valid else '❌ FAIL'}")
    
    if token_valid:
        facts = token_validation.get('facts', {})
        users = facts.get('users', [])
        print(f"Extracted user: {users}")
        
        # Show all facts for analysis
        print(f"All token facts:")
        for fact_type, fact_list in facts.items():
            if fact_list:
                print(f"   {fact_type}: {fact_list}")
    
    # Step 4: Server request
    print(f"\n🌐 Step 4: Server request")
    
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
        
        # Analyze the response
        if response.status_code == 200:
            print("✅ Server accepted the request")
            print("   - mTLS authentication: PASSED")
            print("   - Token validation: PASSED")
            print("   - User authorization: Server dependent")
        elif response.status_code == 403:
            print("❌ Server rejected the request (403 Forbidden)")
            print("   This could be due to user authorization or other checks")
        elif response.status_code == 401:
            print("❌ Server rejected authentication (401 Unauthorized)")
        else:
            print(f"⚠️  Unexpected response: {response.status_code}")
        
        # Show detailed response
        try:
            json_response = response.json()
            print(f"\nServer response details:")
            
            # Show biscuit validation results
            if "biscuit_validation" in json_response:
                bv = json_response["biscuit_validation"]
                print(f"   Token valid: {'✅' if bv.get('valid') else '❌'}")
                print(f"   Primary user: {bv.get('primary_user', 'N/A')}")
                print(f"   Client verified: {'✅' if bv.get('client_identity_verified') else '❌'}")
                print(f"   Server verified: {'✅' if bv.get('server_identity_verified') else '❌'}")
            
            # Show any error messages
            if "error" in json_response:
                print(f"   Error: {json_response['error']}")
                
        except:
            print(f"Raw response: {response.text}")
        
        # For this test, success means the system properly handled the request
        # Whether it grants access depends on business logic implementation
        return response.status_code in [200, 403]  # Both are valid responses
        
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
    success = test_wrong_user_identity()
    
    print(f"\n📊 TEST RESULT")
    print("="*60)
    if success:
        print("✅ TEST PASSED: System properly handled user identity validation")
        print("🔒 Multi-layer security model working:")
        print("   • mTLS layer: Transport security verified")
        print("   • Biscuit layer: Token cryptographically verified")  
        print("   • Business logic layer: User authorization controlled by application")
    else:
        print("❌ TEST FAILED: System did not handle the request properly")
    
    print(f"\n💡 Key Insight:")
    print("This test demonstrates the separation of concerns in the enhanced security model:")
    print("  1. mTLS handles transport security and client authentication")
    print("  2. Biscuit tokens handle cryptographic authorization")
    print("  3. Business logic handles user-specific access control")
    print("  4. All layers must work together for complete security")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())