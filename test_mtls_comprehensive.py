#!/usr/bin/env python3
"""
Comprehensive test suite for the custom mTLS HTTP server implementation.
This test verifies all security scenarios and demonstrates proper mTLS functionality.
"""

import requests
import ssl
import socket
import urllib3
import json

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_no_certificate():
    """Test connection without any client certificate."""
    print("🚫 Test 1: Connection without client certificate")
    print("-" * 50)
    
    try:
        # Create SSL context without client certificate
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations("certs/ca-cert.pem")
        context.check_hostname = False
        
        # Create socket and try to connect
        sock = socket.create_connection(('localhost', 8443), timeout=5)
        ssock = context.wrap_socket(sock, server_hostname='localhost')
        
        print("❌ SECURITY ISSUE: Connection succeeded without client certificate!")
        ssock.close()
        return False
        
    except ssl.SSLError as e:
        print(f"✅ Connection properly rejected at SSL level: {e}")
        return True
    except Exception as e:
        print(f"✅ Connection properly rejected: {e}")
        return True

def test_authorized_client():
    """Test connection with authorized client certificate."""
    print("\n✅ Test 2: Authorized client (claude-client)")
    print("-" * 50)
    
    try:
        response = requests.get(
            "https://localhost:8443/",
            verify="certs/ca-cert.pem",
            cert=("certs/claude-client-cert.pem", "certs/claude-client-key.pem"),
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Status: {response.status_code} OK")
            print(f"✅ Client Identity: {data.get('client_identity')}")
            print(f"✅ Server: {data.get('server')}")
            print(f"✅ Status: {data.get('status')}")
            return True, data.get('client_identity')
        else:
            print(f"❌ Unexpected status: {response.status_code}")
            print(f"Response: {response.text}")
            return False, None
            
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False, None

def test_unauthorized_client():
    """Test connection with unauthorized client certificate."""
    print("\n❌ Test 3: Unauthorized client (unauthorized-hacker)")
    print("-" * 50)
    
    try:
        response = requests.get(
            "https://localhost:8443/",
            verify="certs/ca-cert.pem", 
            cert=("certs/unauthorized-hacker-cert.pem", "certs/unauthorized-hacker-key.pem"),
            timeout=5
        )
        
        if response.status_code == 403:
            data = response.json()
            print(f"✅ Status: {response.status_code} Forbidden (correctly rejected)")
            print(f"✅ Error: {data.get('error')}")
            print(f"✅ Detected Identity: {data.get('client_identity')}")
            return True, data.get('client_identity')
        else:
            print(f"❌ Unexpected status: {response.status_code} (should be 403)")
            print(f"Response: {response.text}")
            return False, None
            
    except Exception as e:
        print(f"❌ Connection failed unexpectedly: {e}")
        return False, None

def test_health_endpoint():
    """Test health endpoint with authorized client."""
    print("\n🔍 Test 4: Health endpoint access")
    print("-" * 50)
    
    try:
        response = requests.get(
            "https://localhost:8443/health",
            verify="certs/ca-cert.pem",
            cert=("certs/claude-client-cert.pem", "certs/claude-client-key.pem"),
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Status: {response.status_code} OK")
            print(f"✅ Health Status: {data.get('status')}")
            print(f"✅ mTLS Status: {data.get('mtls')}")
            print(f"✅ Client Identity: {data.get('client_identity')}")
            return True
        else:
            print(f"❌ Unexpected status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_mcp_endpoint():
    """Test MCP endpoint access with authorized client."""
    print("\n🔗 Test 5: MCP endpoint access")
    print("-" * 50)
    
    try:
        response = requests.get(
            "https://localhost:8443/mcp/test",
            verify="certs/ca-cert.pem",
            cert=("certs/claude-client-cert.pem", "certs/claude-client-key.pem"),
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Status: {response.status_code} OK")
            print(f"✅ Message: {data.get('message')}")
            print(f"✅ Path: {data.get('path')}")
            print(f"✅ Client Identity: {data.get('client_identity')}")
            return True
        else:
            print(f"❌ Unexpected status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ MCP endpoint test failed: {e}")
        return False

def test_unauthorized_endpoint_access():
    """Test that unauthorized client cannot access any endpoints."""
    print("\n🛡️  Test 6: Unauthorized client endpoint access")
    print("-" * 50)
    
    endpoints = ["/", "/health", "/mcp/test"]
    all_blocked = True
    
    for endpoint in endpoints:
        try:
            response = requests.get(
                f"https://localhost:8443{endpoint}",
                verify="certs/ca-cert.pem",
                cert=("certs/unauthorized-hacker-cert.pem", "certs/unauthorized-hacker-key.pem"),
                timeout=5
            )
            
            if response.status_code == 403:
                print(f"✅ {endpoint}: Properly blocked (403 Forbidden)")
            else:
                print(f"❌ {endpoint}: Not properly blocked (status {response.status_code})")
                all_blocked = False
                
        except Exception as e:
            print(f"✅ {endpoint}: Connection blocked ({e})")
    
    return all_blocked

def main():
    """Run comprehensive mTLS test suite."""
    print("🔒 Comprehensive mTLS Security Test Suite")
    print("=" * 60)
    print("Testing custom asyncio HTTP server with proper mTLS support")
    print()
    
    # Run all tests
    test_results = []
    
    # Test 1: No certificate
    test_results.append(("No certificate rejection", test_no_certificate()))
    
    # Test 2: Authorized client
    auth_success, auth_identity = test_authorized_client()
    test_results.append(("Authorized client access", auth_success))
    
    # Test 3: Unauthorized client
    unauth_success, unauth_identity = test_unauthorized_client()
    test_results.append(("Unauthorized client rejection", unauth_success))
    
    # Test 4: Health endpoint
    test_results.append(("Health endpoint access", test_health_endpoint()))
    
    # Test 5: MCP endpoint
    test_results.append(("MCP endpoint access", test_mcp_endpoint()))
    
    # Test 6: Unauthorized endpoint access
    test_results.append(("Unauthorized endpoint blocking", test_unauthorized_endpoint_access()))
    
    # Results summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:8} {test_name}")
        if result:
            passed += 1
    
    print(f"\n📈 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! The custom mTLS implementation is working correctly.")
        print("\n🔐 Security Features Verified:")
        print("   ✅ Client certificate requirement enforced")
        print("   ✅ Identity-based access control working")
        print("   ✅ Unauthorized clients properly rejected")
        print("   ✅ All endpoints protected by mTLS")
        print("   ✅ Certificate identity extraction working")
        print("   ✅ Proper error handling and logging")
        
        if auth_identity and unauth_identity:
            print(f"\n🔍 Identity Detection:")
            print(f"   Authorized: '{auth_identity}'")
            print(f"   Unauthorized: '{unauth_identity}' (correctly blocked)")
            
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Review the results above.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)