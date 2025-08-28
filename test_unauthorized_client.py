#!/usr/bin/env python3
"""
Test script to verify that unauthorized clients are properly rejected by the mTLS implementation.
"""

import requests
import ssl
import urllib3
from pathlib import Path

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_unauthorized_client():
    """Test connection with unauthorized client certificate."""
    print("🔒 Testing unauthorized client certificate rejection...")
    print("=" * 60)
    
    try:
        # Create SSL context for unauthorized client
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Load CA certificate to verify server
        context.load_verify_locations("certs/ca-cert.pem")
        
        # Load unauthorized client certificate
        context.load_cert_chain("certs/unauthorized-hacker-cert.pem", "certs/unauthorized-hacker-key.pem")
        
        # Create session with SSL context
        session = requests.Session()
        session.mount('https://', requests.adapters.HTTPAdapter())
        
        # Make request with unauthorized certificate
        print("Attempting connection with unauthorized certificate (CN: unauthorized-hacker)...")
        
        response = session.get(
            "https://localhost:8443/",
            verify="certs/ca-cert.pem",
            cert=("certs/unauthorized-hacker-cert.pem", "certs/unauthorized-hacker-key.pem"),
            timeout=10
        )
        
        if response.status_code in [401, 403]:
            print(f"✅ Unauthorized client properly rejected with status {response.status_code}")
            print(f"Response: {response.text}")
            return True
        else:
            print(f"❌ SECURITY ISSUE: Unauthorized client got status {response.status_code}")
            print(f"Response: {response.text}")
            print("\n⚠️  WARNING: Unauthorized client was not properly rejected!")
            return False
        
    except requests.exceptions.SSLError as e:
        print(f"✅ Connection properly rejected due to SSL error: {e}")
        return True
        
    except requests.exceptions.ConnectionError as e:
        print(f"✅ Connection properly rejected: {e}")
        return True
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def test_authorized_client():
    """Test connection with authorized client certificate for comparison."""
    print("\n🔓 Testing authorized client certificate for comparison...")
    print("=" * 60)
    
    try:
        # Make request with authorized certificate
        print("Attempting connection with authorized certificate (CN: claude-client)...")
        
        response = requests.get(
            "https://localhost:8443/",
            verify="certs/ca-cert.pem",
            cert=("certs/claude-client-cert.pem", "certs/claude-client-key.pem"),
            timeout=10
        )
        
        if response.status_code == 200:
            print(f"✅ Authorized client connected successfully with status {response.status_code}")
            print(f"Response: {response.text}")
            return True
        else:
            print(f"❌ Authorized client got unexpected status {response.status_code}")
            print(f"Response: {response.text}")
            return False
        
    except Exception as e:
        print(f"❌ Authorized client connection failed: {e}")
        return False

if __name__ == "__main__":
    print("🚨 mTLS Unauthorized Client Test")
    print("=" * 60)
    
    # Test unauthorized client
    unauthorized_result = test_unauthorized_client()
    
    # Test authorized client for comparison
    authorized_result = test_authorized_client()
    
    print("\n📊 Test Results:")
    print("=" * 60)
    print(f"Unauthorized client properly rejected: {'✅ PASS' if unauthorized_result else '❌ FAIL'}")
    print(f"Authorized client can connect: {'✅ PASS' if authorized_result else '❌ FAIL'}")
    
    if not unauthorized_result:
        print("\n⚠️  SECURITY CONCERN:")
        print("The mTLS implementation is not properly rejecting unauthorized clients.")
        print("This indicates the middleware needs to be fixed to properly validate client certificates.")
    else:
        print("\n🎉 mTLS security is working correctly!")