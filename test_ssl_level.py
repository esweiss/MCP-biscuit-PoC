#!/usr/bin/env python3
"""
Test to verify if SSL-level certificate validation is working.
This will help us understand if the issue is at TLS handshake level or application level.
"""

import ssl
import socket
import sys
from pathlib import Path

def test_ssl_connection(cert_file, key_file, ca_file, client_name):
    """Test SSL connection with specific client certificate."""
    print(f"\n🔒 Testing SSL connection with certificate: {client_name}")
    print("=" * 60)
    
    try:
        # Create SSL context for client
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(ca_file)
        context.load_cert_chain(cert_file, key_file)
        context.check_hostname = False  # We're using localhost
        
        # Create socket and connect
        sock = socket.create_connection(('localhost', 8443), timeout=10)
        
        # Wrap with SSL
        ssock = context.wrap_socket(sock, server_hostname='localhost')
        
        print(f"✅ SSL handshake successful!")
        print(f"SSL version: {ssock.version()}")
        print(f"Cipher: {ssock.cipher()}")
        
        # Try to send a simple HTTP request
        request = "GET / HTTP/1.1\r\nHost: localhost:8443\r\nConnection: close\r\n\r\n"
        ssock.send(request.encode())
        
        # Read response
        response = ssock.recv(4096).decode()
        print(f"Response received: {response[:100]}...")
        
        # Check response status
        status_line = response.split('\n')[0]
        print(f"Status: {status_line}")
        
        ssock.close()
        return True, status_line
        
    except ssl.SSLError as e:
        print(f"❌ SSL Error: {e}")
        return False, f"SSL Error: {e}"
    except Exception as e:
        print(f"❌ Connection Error: {e}")
        return False, f"Error: {e}"

def test_no_certificate():
    """Test connection without client certificate."""
    print(f"\n🚫 Testing SSL connection without client certificate")
    print("=" * 60)
    
    try:
        # Create SSL context without client certificate
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations("certs/ca-cert.pem")
        context.check_hostname = False
        
        # Create socket and connect
        sock = socket.create_connection(('localhost', 8443), timeout=10)
        
        # Wrap with SSL - this should fail with CERT_REQUIRED
        ssock = context.wrap_socket(sock, server_hostname='localhost')
        
        print(f"❌ SECURITY ISSUE: SSL handshake succeeded without client certificate!")
        ssock.close()
        return True, "No certificate accepted"
        
    except ssl.SSLError as e:
        print(f"✅ SSL properly rejected connection without certificate: {e}")
        return False, f"SSL rejected: {e}"
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False, f"Error: {e}"

if __name__ == "__main__":
    print("🚨 SSL-Level mTLS Test")
    print("=" * 60)
    print("This test connects directly to the SSL port to check certificate validation")
    print("at the TLS handshake level, bypassing ASGI middleware.")
    print()
    
    # Test 1: No certificate (should fail at SSL level)
    no_cert_success, no_cert_msg = test_no_certificate()
    
    # Test 2: Authorized certificate
    auth_success, auth_msg = test_ssl_connection(
        "certs/claude-client-cert.pem", 
        "certs/claude-client-key.pem",
        "certs/ca-cert.pem",
        "claude-client (authorized)"
    )
    
    # Test 3: Unauthorized certificate  
    unauth_success, unauth_msg = test_ssl_connection(
        "certs/unauthorized-hacker-cert.pem",
        "certs/unauthorized-hacker-key.pem", 
        "certs/ca-cert.pem",
        "unauthorized-hacker (unauthorized)"
    )
    
    print("\n📊 SSL-Level Test Results:")
    print("=" * 60)
    print(f"No certificate rejected: {'✅ PASS' if not no_cert_success else '❌ FAIL'}")
    print(f"Authorized cert accepted: {'✅ PASS' if auth_success else '❌ FAIL'}")
    print(f"Unauthorized cert result: {'⚠️  ACCEPTED' if unauth_success else '❌ REJECTED'}")
    
    print(f"\nDetailed results:")
    print(f"  No cert: {no_cert_msg}")
    print(f"  Authorized: {auth_msg}")
    print(f"  Unauthorized: {unauth_msg}")
    
    if unauth_success and auth_success:
        if unauth_msg == auth_msg:
            print("\n⚠️  FINDING: Both authorized and unauthorized certificates get identical responses.")
            print("This suggests the server is accepting any certificate signed by the CA,")
            print("and the application-level authorization (middleware) is not working properly.")
        else:
            print("\n✅ GOOD: Different responses suggest application-level filtering is working.")
    elif not unauth_success and not auth_success:
        print("\n❌ ISSUE: Both authorized and unauthorized certificates are being rejected.")
        print("This suggests a configuration problem with the SSL setup.")
    elif auth_success and not unauth_success:
        print("\n✅ EXCELLENT: SSL-level filtering is working perfectly!")
        print("Authorized certificates are accepted, unauthorized are rejected at TLS handshake.")
    else:
        print("\n❓ UNEXPECTED: Unauthorized cert accepted but authorized cert rejected.")