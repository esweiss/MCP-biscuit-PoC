#!/usr/bin/env python3
"""
Simple test script to demonstrate mTLS functionality
"""
import asyncio
import ssl
import httpx
import sys

async def test_mtls_connection():
    """Test mTLS connection to the MCP server."""
    
    # Create SSL context for client
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    
    # Load client certificate and key
    ssl_context.load_cert_chain("certs/claude-client-cert.pem", "certs/claude-client-key.pem")
    
    # Load CA certificate for server verification
    ssl_context.load_verify_locations("certs/ca-cert.pem")
    
    # Don't verify hostname since we're using localhost
    ssl_context.check_hostname = False
    
    try:
        async with httpx.AsyncClient(verify=ssl_context) as client:
            print("Testing mTLS connection to MCP server...")
            
            # Test basic connection
            response = await client.get("https://localhost:8443/")
            print(f"✅ mTLS connection successful!")
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text[:100]}...")
            
            # Test SSE endpoint
            try:
                response = await client.get("https://localhost:8443/sse")
                print(f"✅ SSE endpoint accessible!")
                print(f"Status: {response.status_code}")
            except Exception as e:
                print(f"ℹ️  SSE endpoint response: {e}")
            
    except httpx.ConnectError as e:
        print(f"❌ Connection failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    
    return True

async def test_unauthorized_connection():
    """Test connection without client certificate (should fail)."""
    
    print("\nTesting unauthorized connection (no client cert)...")
    
    # Create SSL context without client certificate
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_verify_locations("certs/ca-cert.pem")
    ssl_context.check_hostname = False
    
    try:
        async with httpx.AsyncClient(verify=ssl_context) as client:
            response = await client.get("https://localhost:8443/")
            print(f"❌ Unexpected success: {response.status_code}")
            return False
    except httpx.ConnectError as e:
        print(f"✅ Connection properly rejected: {e}")
        return True
    except Exception as e:
        print(f"✅ Connection rejected with error: {e}")
        return True

async def test_wrong_certificate():
    """Test connection with wrong client certificate."""
    
    print("\nTesting connection with unauthorized certificate...")
    
    # Create an unauthorized client cert
    import subprocess
    import os
    
    # Generate a rogue client certificate (not signed by our CA)
    if not os.path.exists("certs/rogue-client-cert.pem"):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", "certs/rogue-client-key.pem",
            "-out", "certs/rogue-client-cert.pem", "-days", "365", "-nodes",
            "-subj", "/C=US/ST=Demo/L=Demo/O=Rogue-Client/CN=rogue-client"
        ], check=True, cwd=".", capture_output=True)
    
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_cert_chain("certs/rogue-client-cert.pem", "certs/rogue-client-key.pem")
    ssl_context.load_verify_locations("certs/ca-cert.pem")
    ssl_context.check_hostname = False
    
    try:
        async with httpx.AsyncClient(verify=ssl_context) as client:
            response = await client.get("https://localhost:8443/")
            print(f"❌ Rogue certificate unexpectedly accepted: {response.status_code}")
            return False
    except Exception as e:
        print(f"✅ Rogue certificate properly rejected: {e}")
        return True

async def main():
    """Run mTLS tests."""
    print("🔒 MCP Biscuit mTLS Test Suite")
    print("=" * 50)
    
    # Test 1: Authorized connection
    success1 = await test_mtls_connection()
    
    # Test 2: Unauthorized connection
    success2 = await test_unauthorized_connection()
    
    # Test 3: Wrong certificate
    success3 = await test_wrong_certificate()
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    print(f"  ✅ Authorized client: {'PASS' if success1 else 'FAIL'}")
    print(f"  ✅ No certificate rejection: {'PASS' if success2 else 'FAIL'}")
    print(f"  ✅ Wrong certificate rejection: {'PASS' if success3 else 'FAIL'}")
    
    if success1 and success2 and success3:
        print("\n🎉 All mTLS tests PASSED! The security model is working correctly.")
        return 0
    else:
        print("\n❌ Some tests FAILED. Check the server configuration.")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))