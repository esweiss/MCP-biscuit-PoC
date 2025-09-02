#!/usr/bin/env python3
"""
mTLS + Biscuit Token Client
Demonstrates enhanced security by combining mTLS client certificates with Biscuit token validation.

This client:
1. Loads an existing Biscuit token
2. Adds an mTLS attestation block with client identity and server audience
3. Connects to the mTLS server using client certificates
4. Sends the enhanced token for dual validation
"""

import os
import sys
import ssl
import json
import requests
import argparse
from pathlib import Path

# Add the project root to Python path for imports
sys.path.append(str(Path(__file__).parent.parent))

from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser

class MTLSBiscuitClient:
    """Client that combines mTLS authentication with Biscuit token authorization."""
    
    def __init__(self, server_url="https://localhost:8443", 
                 ca_cert_path="certs/ca-cert.pem",
                 client_cert_path="certs/claude-client-cert.pem",
                 client_key_path="certs/claude-client-key.pem"):
        self.server_url = server_url
        self.ca_cert_path = ca_cert_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        
        # Get certificate identities
        self.client_identity = self._extract_cert_identity(client_cert_path)
        self.server_identity = "mcp-server"  # Server's certificate CN
        
        # Initialize Biscuit tools
        self.biscuit_generator = None
        self.biscuit_parser = None
        
    def _extract_cert_identity(self, cert_path: str) -> str:
        """Extract the Common Name from a certificate file."""
        import ssl
        import cryptography.x509
        from cryptography.x509.oid import NameOID
        
        try:
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                cert = cryptography.x509.load_pem_x509_certificate(cert_data)
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                return cn
        except Exception as e:
            print(f"⚠️  Failed to extract identity from {cert_path}: {e}")
            # Fallback to filename-based identity
            return Path(cert_path).stem.replace("-cert", "")
    
    def setup_biscuit_tools(self, private_key_hex: str, public_key_hex: str):
        """Initialize Biscuit token tools with keys."""
        self.biscuit_generator = BiscuitGenerator(private_key_hex)
        self.biscuit_parser = BiscuitParser(public_key_hex)
    
    def create_enhanced_token(self, base_token: str) -> str:
        """Add mTLS attestation block to an existing Biscuit token."""
        if not self.biscuit_generator:
            raise Exception("Biscuit generator not initialized. Call setup_biscuit_tools() first.")
        
        print(f"🔐 Adding mTLS attestation block:")
        print(f"   Client Identity: {self.client_identity}")
        print(f"   Server Audience: {self.server_identity}")
        
        enhanced_token = self.biscuit_generator.add_mtls_attestation_block(
            base_token, 
            self.client_identity, 
            self.server_identity,
            public_key_hex=self.biscuit_parser.public_key.to_hex() if self.biscuit_parser and self.biscuit_parser.public_key else None
        )
        
        print(f"✅ Enhanced token created (blocks: {self._get_block_count(enhanced_token)})")
        return enhanced_token
    
    def _get_block_count(self, token_b64: str) -> int:
        """Get the number of blocks in a token."""
        try:
            if self.biscuit_parser:
                result = self.biscuit_parser.parse_unverified(token_b64)
                return result.get("block_count", 0)
        except:
            pass
        return 0
    
    def validate_token_locally(self, token_b64: str) -> dict:
        """Validate the enhanced token locally before sending."""
        if not self.biscuit_parser:
            return {"status": "parser_not_initialized"}
        
        print(f"🔍 Validating enhanced token locally...")
        
        # Basic verification
        verification_result = self.biscuit_parser.verify_and_extract_facts(token_b64)
        print(f"   Token verification: {verification_result.get('verification', 'FAILED')}")
        
        # mTLS attestation validation
        mtls_result = self.biscuit_parser.validate_mtls_attestation(
            token_b64, 
            self.client_identity, 
            self.server_identity
        )
        
        print(f"   mTLS validation: {'✅ PASS' if mtls_result.get('mtls_validation') else '❌ FAIL'}")
        
        if not mtls_result.get("mtls_validation"):
            details = mtls_result.get("validation_details", {})
            for check, result in details.items():
                if "_error" in check:
                    print(f"      {check}: {result}")
        
        return {
            "verification": verification_result,
            "mtls_validation": mtls_result
        }
    
    def make_request(self, endpoint: str, token: str) -> dict:
        """Make an HTTPS request with mTLS authentication and Biscuit token."""
        try:
            print(f"🌐 Connecting to {self.server_url}{endpoint}")
            print(f"   Using client certificate: {self.client_cert_path}")
            print(f"   Token blocks: {self._get_block_count(token)}")
            
            # Make request with mTLS
            response = requests.get(
                f"{self.server_url}{endpoint}",
                verify=self.ca_cert_path,
                cert=(self.client_cert_path, self.client_key_path),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=10
            )
            
            result = {
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "response": response.text,
                "headers": dict(response.headers)
            }
            
            if result["success"]:
                print(f"✅ Request successful: {response.status_code}")
            else:
                print(f"❌ Request failed: {response.status_code}")
            
            try:
                result["json_response"] = response.json()
            except:
                pass
            
            return result
            
        except Exception as e:
            print(f"❌ Request failed: {e}")
            return {
                "status_code": 0,
                "success": False,
                "error": str(e)
            }

def main():
    parser = argparse.ArgumentParser(description="mTLS + Biscuit Token Client")
    parser.add_argument("--base-token", required=True, help="Base Biscuit token to enhance")
    parser.add_argument("--private-key", required=True, help="Biscuit private key (hex)")
    parser.add_argument("--public-key", required=True, help="Biscuit public key (hex)")
    parser.add_argument("--endpoint", default="/", help="Server endpoint to test")
    parser.add_argument("--server-url", default="https://localhost:8443", help="Server URL")
    parser.add_argument("--client-cert", default="certs/claude-client-cert.pem", help="Client certificate path")
    parser.add_argument("--client-key", default="certs/claude-client-key.pem", help="Client key path")
    parser.add_argument("--ca-cert", default="certs/ca-cert.pem", help="CA certificate path")
    
    # Additional test scenarios
    parser.add_argument("--wrong-client-identity", help="Use wrong client identity for testing")
    parser.add_argument("--wrong-server-audience", help="Use wrong server audience for testing")
    
    args = parser.parse_args()
    
    print("🚀 mTLS + Biscuit Token Client")
    print("=" * 50)
    
    # Initialize client
    client = MTLSBiscuitClient(
        server_url=args.server_url,
        ca_cert_path=args.ca_cert,
        client_cert_path=args.client_cert,
        client_key_path=args.client_key
    )
    
    # Setup Biscuit tools
    client.setup_biscuit_tools(args.private_key, args.public_key)
    
    # Override identities for testing if specified
    if args.wrong_client_identity:
        client.client_identity = args.wrong_client_identity
        print(f"⚠️  Using wrong client identity for testing: {args.wrong_client_identity}")
    
    if args.wrong_server_audience:
        client.server_identity = args.wrong_server_audience
        print(f"⚠️  Using wrong server audience for testing: {args.wrong_server_audience}")
    
    try:
        # Step 1: Create enhanced token
        print(f"\n📝 Step 1: Creating enhanced token")
        enhanced_token = client.create_enhanced_token(args.base_token)
        
        # Step 2: Validate token locally
        print(f"\n🔍 Step 2: Local validation")
        validation_result = client.validate_token_locally(enhanced_token)
        
        # Step 3: Make request to server
        print(f"\n🌐 Step 3: Server request")
        request_result = client.make_request(args.endpoint, enhanced_token)
        
        # Summary
        print(f"\n📊 Summary")
        print("=" * 50)
        token_valid = validation_result.get("mtls_validation", {}).get("mtls_validation", False)
        request_successful = request_result.get("success", False)
        
        print(f"Token validation: {'✅ PASS' if token_valid else '❌ FAIL'}")
        print(f"Server request: {'✅ PASS' if request_successful else '❌ FAIL'}")
        
        if request_result.get("json_response"):
            print(f"Server response: {json.dumps(request_result['json_response'], indent=2)}")
        
        return 0 if (token_valid and request_successful) else 1
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())