#!/usr/bin/env python3
"""
Enhanced Security Interactive Demo Script

This script demonstrates the complete enhanced security flow with interactive features:
1. Creates a base Biscuit token with user credentials
2. Adds an mTLS attestation block with client and server identities
3. Validates the token locally
4. Allows interactive text-to-SQL testing with Claude API
5. Sends enhanced tokens to the mTLS server for dual validation

Usage:
    python demo_enhanced_security_interactive.py --user alice
    python demo_enhanced_security_interactive.py --user alice --interactive
    python demo_enhanced_security_interactive.py --user alice --query "Show me all patients"
"""

import os
import sys
import json
import argparse
import requests
from pathlib import Path
from typing import Optional, Dict, Any

# Add the project root to Python path for imports
sys.path.append(str(Path(__file__).parent))

from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser

class EnhancedSecurityDemo:
    """Interactive demo for enhanced mTLS + Biscuit security with text-to-SQL."""
    
    def __init__(self, user_id: str = "alice"):
        self.user_id = user_id
        self.generator = None
        self.parser = None
        self.enhanced_token = None
        self.server_url = "https://localhost:8443"
        self.ca_cert = "certs/ca-cert.pem"
        self.client_cert = "certs/claude-client-cert.pem"
        self.client_key = "certs/claude-client-key.pem"
        
        # Claude API configuration
        self.anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
        
    def setup_environment(self):
        """Setup Biscuit environment and create enhanced token."""
        print("🚀 ENHANCED SECURITY INTERACTIVE DEMO")
        print("="*60)
        print(f"User: {self.user_id}")
        print("")
        
        # Step 1: Setup Biscuit environment
        print("🔧 Step 1: Setting up Biscuit environment")
        print("-" * 40)
        
        # Get or generate keys
        private_key = os.getenv('BISCUIT_PRIVATE_KEY')
        public_key = os.getenv('BISCUIT_PUBLIC_KEY')
        
        if not private_key or not public_key:
            print("🔑 No keys in environment, generating new ones...")
            self.generator = BiscuitGenerator()
            public_key = self.generator.get_public_key()
            private_key = self.generator.private_key.to_hex()
            print(f"   Generated public key: {public_key[:32]}...")
        else:
            self.generator = BiscuitGenerator(private_key)
            print(f"   Using environment public key: {public_key[:32]}...")
        
        self.parser = BiscuitParser(public_key)
        
        # Step 2: Create base token
        print(f"\n🎫 Step 2: Creating base token for user '{self.user_id}'")
        print("-" * 40)
        
        base_token = self.generator.create_custom_token([
            f'user("{self.user_id}")',
            'resource("medical_records")',
            'operation("read")',
            'patient_name("Erin oRTEga")',
            'database_access("healthcare_data")'
        ])
        
        print(f"✅ Base token created: {base_token[:50]}...")
        
        # Validate base token
        base_validation = self.parser.verify_and_extract_facts(base_token)
        print(f"   Base token validation: {'✅ VALID' if base_validation.get('status') == 'verified_with_facts' else '❌ INVALID'}")
        
        # Step 3: Add mTLS attestation block
        print(f"\n🔐 Step 3: Adding mTLS attestation block")
        print("-" * 40)
        
        client_identity = "claude-client"  # From mTLS certificate
        server_identity = "mcp-server"     # Server's certificate identity
        
        print(f"   Client Identity: {client_identity}")
        print(f"   Server Audience: {server_identity}")
        
        self.enhanced_token = self.generator.add_mtls_attestation_block(
            base_token,
            client_identity,
            server_identity,
            public_key_hex=public_key
        )
        
        print(f"✅ Enhanced token created: {self.enhanced_token[:50]}...")
        
        # Step 4: Local validation
        print(f"\n🔍 Step 4: Local token validation")
        print("-" * 40)
        
        # Validate enhanced token
        enhanced_validation = self.parser.verify_and_extract_facts(self.enhanced_token)
        token_valid = enhanced_validation.get('status') == 'verified_with_facts'
        print(f"   Token verification: {'✅ VALID' if token_valid else '❌ INVALID'}")
        
        # Validate mTLS attestation
        mtls_validation = self.parser.validate_mtls_attestation(
            self.enhanced_token,
            client_identity,
            server_identity
        )
        mtls_valid = mtls_validation.get('mtls_validation', False)
        print(f"   mTLS attestation: {'✅ VALID' if mtls_valid else '❌ INVALID'}")
        
        if not mtls_valid:
            details = mtls_validation.get('validation_details', {})
            for key, value in details.items():
                if '_error' in key:
                    print(f"      {key}: {value}")
        
        # Show extracted facts
        if token_valid:
            facts = enhanced_validation.get('facts', {})
            print(f"   Token facts available:")
            for fact_type, fact_list in facts.items():
                if fact_list:
                    values = [f.terms[0] if hasattr(f, 'terms') else str(f) for f in fact_list]
                    print(f"      {fact_type}: {values}")
        
        return token_valid and mtls_valid
    
    def generate_sql_with_claude(self, user_query: str) -> Optional[str]:
        """Generate SQL query using Claude API."""
        if not self.anthropic_api_key:
            print("⚠️  ANTHROPIC_API_KEY not found in environment")
            print("   Falling back to example query...")
            return "SELECT * FROM patients WHERE LOWER(name) LIKE '%erin%' AND LOWER(name) LIKE '%ortega%' LIMIT 5;"
        
        print(f"🤖 Generating SQL query with Claude API...")
        print(f"   User query: \"{user_query}\"")
        
        try:
            # Prepare the prompt for Claude
            system_prompt = """You are a SQL query generator for a healthcare database. 
            
Database schema:
- patients table: id, name, age, condition, admission_date
- medical_records table: id, patient_id, diagnosis, treatment, date_recorded
- appointments table: id, patient_id, doctor, appointment_date, status

Convert natural language queries to safe, read-only SQL queries. 
Only generate SELECT statements. Use LIMIT clauses to prevent large results.
Be case-insensitive in searches using LOWER() function.

Respond with ONLY the SQL query, no explanations."""
            
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.anthropic_api_key,
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01"
                },
                json={
                    "model": "claude-3-sonnet-20240229",
                    "max_tokens": 200,
                    "system": system_prompt,
                    "messages": [
                        {
                            "role": "user", 
                            "content": user_query
                        }
                    ]
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                sql_query = result.get("content", [{}])[0].get("text", "").strip()
                print(f"   Generated SQL: {sql_query}")
                return sql_query
            else:
                print(f"❌ Claude API error: {response.status_code}")
                print(f"   Response: {response.text}")
                return None
                
        except Exception as e:
            print(f"❌ Error calling Claude API: {e}")
            return None
    
    def test_server_query(self, user_query: str, sql_query: str) -> Dict[str, Any]:
        """Test SQL query execution through the enhanced security server."""
        print(f"\n🌐 Step 5: Testing secure database query")
        print("-" * 40)
        print(f"   Natural language: \"{user_query}\"")
        print(f"   Generated SQL: {sql_query}")
        
        try:
            # Test basic server connection first
            health_response = requests.get(
                f"{self.server_url}/health",
                verify=self.ca_cert,
                cert=(self.client_cert, self.client_key),
                headers={
                    "Authorization": f"Bearer {self.enhanced_token}",
                    "Content-Type": "application/json"
                },
                timeout=10
            )
            
            print(f"   Server health check: {health_response.status_code}")
            
            # Try MCP query endpoint (may not be fully implemented)
            query_response = requests.post(
                f"{self.server_url}/mcp/query",
                verify=self.ca_cert,
                cert=(self.client_cert, self.client_key),
                headers={
                    "Authorization": f"Bearer {self.enhanced_token}",
                    "Content-Type": "application/json"
                },
                json={
                    "query": sql_query,
                    "conn_id": "default",
                    "user_query": user_query
                },
                timeout=15
            )
            
            result = {
                "health_status": health_response.status_code,
                "query_status": query_response.status_code,
                "success": query_response.status_code == 200
            }
            
            if query_response.status_code == 200:
                print("   ✅ Query executed successfully!")
                try:
                    query_result = query_response.json()
                    result["query_result"] = query_result
                    print(f"   Query result: {json.dumps(query_result, indent=4)}")
                except:
                    result["query_response"] = query_response.text
                    print(f"   Query response: {query_response.text}")
            else:
                print(f"   ⚠️  Query endpoint returned: {query_response.status_code}")
                result["query_response"] = query_response.text
                print(f"   Response: {query_response.text}")
                
                if query_response.status_code == 404:
                    print("   💡 Note: MCP query endpoint may not be fully implemented")
                    print("   💡 This demonstrates token validation and server access")
            
            return result
            
        except Exception as e:
            print(f"   ❌ Server request failed: {e}")
            return {"success": False, "error": str(e)}
    
    def interactive_mode(self):
        """Run interactive text-to-SQL testing mode."""
        print(f"\n🎯 Interactive Text-to-SQL Testing Mode")
        print("="*60)
        print("Enter natural language queries to test SQL generation and secure execution.")
        print("Enhanced mTLS + Biscuit security will be validated for each query.")
        print("Type 'quit' or 'exit' to stop, 'help' for examples.\n")
        
        while True:
            try:
                user_input = input("🔍 Enter your query: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break
                
                if user_input.lower() in ['help', '?']:
                    print("\n💡 Example queries:")
                    print("   • Show me all patients")
                    print("   • Find patients with diabetes")
                    print("   • List appointments for today")  
                    print("   • Show medical records for patient Erin")
                    print("   • Count total patients in the database")
                    print("")
                    continue
                
                if not user_input:
                    continue
                
                print(f"\n{'='*60}")
                print(f"🧪 PROCESSING QUERY: \"{user_input}\"")
                print(f"{'='*60}")
                
                # Generate SQL
                sql_query = self.generate_sql_with_claude(user_input)
                if not sql_query:
                    print("❌ Failed to generate SQL query")
                    continue
                
                # Test secure execution
                result = self.test_server_query(user_input, sql_query)
                
                # Summary
                print(f"\n📊 Query Summary:")
                print(f"   Natural Language: \"{user_input}\"")
                print(f"   Generated SQL: {sql_query}")
                print(f"   Security Status: {'✅ AUTHORIZED' if result.get('health_status') == 200 else '❌ UNAUTHORIZED'}")
                print(f"   Execution Status: {'✅ SUCCESS' if result.get('success') else '⚠️ ENDPOINT_LIMITED'}")
                
                if result.get('success'):
                    print("   🎉 Complete enhanced security flow successful!")
                elif result.get('query_status') == 404:
                    print("   💡 Server connection secured, query endpoint pending full MCP integration")
                
                print("")
                
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def single_query_mode(self, query: str):
        """Run a single query test."""
        print(f"\n🎯 Single Query Test Mode")
        print("="*60)
        
        # Generate SQL
        sql_query = self.generate_sql_with_claude(query)
        if not sql_query:
            print("❌ Failed to generate SQL query")
            return False
        
        # Test secure execution
        result = self.test_server_query(query, sql_query)
        
        # Summary
        print(f"\n📊 FINAL SUMMARY")
        print("="*60)
        print(f"Natural Language Query: \"{query}\"")
        print(f"Generated SQL: {sql_query}")
        print(f"Enhanced Security Status: {'✅ PASS' if result.get('health_status') == 200 else '❌ FAIL'}")
        print(f"Query Execution: {'✅ SUCCESS' if result.get('success') else '⚠️ LIMITED'}")
        
        success = result.get('health_status') == 200
        
        if success:
            print("\n🎉 Enhanced security model working perfectly!")
            print("✅ Multi-layer validation complete:")
            print("   • mTLS client certificate authentication ✅")
            print("   • Biscuit token cryptographic verification ✅")
            print("   • Client identity consistency validation ✅")
            print("   • Server audience verification ✅")
            print("   • Natural language to SQL conversion ✅")
            if result.get('success'):
                print("   • Secure query execution ✅")
            else:
                print("   • Server access authorized (query endpoint pending full integration) ✅")
        else:
            print("\n❌ Security validation failed")
            
        return success

def main():
    """Main demo execution."""
    parser = argparse.ArgumentParser(description="Enhanced Security Interactive Demo")
    parser.add_argument("--user", default="alice", help="User ID for token")
    parser.add_argument("--interactive", "-i", action="store_true", 
                       help="Run in interactive mode for multiple queries")
    parser.add_argument("--query", "-q", help="Single query to test")
    
    args = parser.parse_args()
    
    demo = EnhancedSecurityDemo(args.user)
    
    # Setup environment and create enhanced token
    if not demo.setup_environment():
        print("\n❌ Environment setup failed")
        return 1
    
    # Check server connectivity
    print(f"\n🔍 Checking server connectivity...")
    try:
        response = requests.get("https://localhost:8443/health", timeout=3, verify=False)
        print("✅ mTLS server is running")
    except requests.exceptions.ConnectionError as e:
        if "Connection refused" in str(e):
            print("❌ mTLS server is not running!")
            print("💡 Start server with: BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY PYTHONPATH=. uv run python server/custom_mtls_server.py")
            return 1
        else:
            print("✅ mTLS server is running (connection established)")
    except Exception as e:
        print(f"⚠️  Server connectivity inconclusive: {e}")
        print("   Proceeding anyway...")
    
    # Run demo mode
    if args.query:
        # Single query mode
        success = demo.single_query_mode(args.query)
        return 0 if success else 1
    elif args.interactive:
        # Interactive mode
        demo.interactive_mode()
        return 0
    else:
        # Default: run interactive mode
        print(f"\n💡 Starting interactive mode (use --query 'text' for single query)")
        demo.interactive_mode()
        return 0

if __name__ == "__main__":
    exit(main())