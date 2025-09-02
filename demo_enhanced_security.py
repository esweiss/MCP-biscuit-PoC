#!/usr/bin/env python3
"""
Enhanced Security Demo Script

This script demonstrates the complete enhanced security flow:
1. Creates a base Biscuit token with user credentials
2. Adds an mTLS attestation block with client and server identities
3. Validates the token locally
4. Sends the enhanced token to the mTLS server for dual validation

Usage:
    python demo_enhanced_security.py --user alice --endpoint /
"""

import os
import sys
import json
import argparse
from pathlib import Path

# Add the project root to Python path for imports
sys.path.append(str(Path(__file__).parent))

from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser

def load_env_file():
    """Load environment variables from .env file."""
    env_file = Path(__file__).parent / '.env'
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value
        print(f"✅ Loaded environment variables from {env_file}")
    else:
        print(f"⚠️  .env file not found at {env_file}")

# Load environment variables at module import
load_env_file()

def generate_sql_with_claude(user_query: str) -> str:
    """Generate SQL query using Claude API for text-to-SQL conversion."""
    import requests
    
    anthropic_api_key = os.getenv('ANTHROPIC_API_KEY')
    if not anthropic_api_key:
        raise Exception("ANTHROPIC_API_KEY not found in environment. This is required for text-to-SQL conversion.")
    
    print(f"🤖 Converting text to SQL: \"{user_query}\"")
    
    try:
        # Prepare the prompt for Claude
        system_prompt = """You are a SQL query generator for a healthcare database used in an MCP security demonstration.

Database schema:
- patients table: id, name, age, condition, admission_date  
- medical_records table: id, patient_id, diagnosis, treatment, date_recorded
- appointments table: id, patient_id, doctor, appointment_date, status

Convert natural language queries to safe, read-only SQL queries for this healthcare demo.
- Only generate SELECT statements
- Use LIMIT clauses to prevent large results (max 10 rows)
- Be case-insensitive in searches using LOWER() function
- Focus on realistic healthcare queries for security testing

Respond with ONLY the SQL query, no explanations or formatting."""
        
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": anthropic_api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01"
            },
            json={
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 150,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_query}]
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            sql_query = result.get("content", [{}])[0].get("text", "").strip()
            # Clean up any markdown formatting
            sql_query = sql_query.replace("```sql", "").replace("```", "").strip()
            return sql_query
        else:
            raise Exception(f"Claude API error: {response.status_code} - {response.text}")
            
    except Exception as e:
        raise Exception(f"Failed to generate SQL: {str(e)}")

def interactive_text_to_sql_demo(user_id: str = "alice"):
    """Run interactive text-to-SQL demo with enhanced security."""
    
    print("🚀 INTERACTIVE TEXT-TO-SQL SECURITY DEMO")  
    print("="*60)
    print("Enter natural language queries to test the complete MCP security flow:")
    print("Text → Claude API → SQL → Enhanced mTLS + Biscuit Security → Server")
    print("")
    print("Type 'quit' to exit, 'help' for examples.")
    print("")
    
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
                print("   • List recent appointments")
                print("   • Show medical records for Erin")
                print("   • Count total patients")
                print("   • Find appointments for today")
                print("")
                continue
                
            if not user_input:
                continue
            
            print(f"\n{'='*70}")
            print(f"🧪 PROCESSING QUERY: \"{user_input}\"")  
            print(f"{'='*70}")
            
            # Run the complete demo flow with this query
            success = run_enhanced_security_demo(
                user_id=user_id, 
                endpoint="/mcp/query",
                user_query=user_input,
                interactive=True
            )
            
            print(f"\n📊 RESULT: {'✅ SUCCESS' if success else '❌ FAILED'}")
            if success:
                print("🔐 Complete enhanced security validation passed!")
            print("")
            
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            print("")

def run_enhanced_security_demo(user_id: str = "alice", endpoint: str = "/", user_query: str = None, interactive: bool = False):
    """Run the enhanced security demonstration with text-to-SQL capabilities."""
    
    print("🚀 ENHANCED SECURITY DEMONSTRATION WITH TEXT-TO-SQL")
    print("="*70)
    print(f"User: {user_id}")
    print(f"Endpoint: {endpoint}")
    if user_query:
        print(f"Query: {user_query}")
    print("")
    
    # Step 1: Setup Biscuit environment
    print("🔧 Step 1: Setting up Biscuit environment")
    print("-" * 40)
    
    # Get or generate keys
    private_key = os.getenv('BISCUIT_PRIVATE_KEY')
    public_key = os.getenv('BISCUIT_PUBLIC_KEY')
    
    if not private_key or not public_key:
        print("🔑 No keys in environment, generating new ones...")
        generator = BiscuitGenerator()
        public_key = generator.get_public_key()
        private_key = generator.private_key.to_hex()
        print(f"   Generated public key: {public_key[:32]}...")
    else:
        generator = BiscuitGenerator(private_key)
        print(f"   Using environment public key: {public_key[:32]}...")
    
    parser = BiscuitParser(public_key)
    
    # Step 2: Create base token
    print(f"\n🎫 Step 2: Creating base token for user '{user_id}'")
    print("-" * 40)
    
    base_token = generator.create_custom_token([
        f'user("{user_id}")',
        'resource("medical_records")',
        'operation("read")',
        'patient_name("Erin oRTEga")'
    ])
    
    print(f"✅ Base token created: {base_token[:50]}...")
    
    # Validate base token
    base_validation = parser.verify_and_extract_facts(base_token)
    print(f"   Base token validation: {'✅ VALID' if base_validation.get('status') == 'verified_with_facts' else '❌ INVALID'}")
    
    # Step 3: Add mTLS attestation block
    print(f"\n🔐 Step 3: Adding mTLS attestation block")
    print("-" * 40)
    
    client_identity = "claude-client"  # From mTLS certificate
    server_identity = "mcp-server"     # Server's certificate identity
    
    print(f"   Client Identity: {client_identity}")
    print(f"   Server Audience: {server_identity}")
    
    enhanced_token = generator.add_mtls_attestation_block(
        base_token,
        client_identity,
        server_identity,
        public_key_hex=public_key
    )
    
    print(f"✅ Enhanced token created: {enhanced_token[:50]}...")
    
    # Step 4: Local validation
    print(f"\n🔍 Step 4: Local token validation")
    print("-" * 40)
    
    # Validate enhanced token
    enhanced_validation = parser.verify_and_extract_facts(enhanced_token)
    token_valid = enhanced_validation.get('status') == 'verified_with_facts'
    print(f"   Token verification: {'✅ VALID' if token_valid else '❌ INVALID'}")
    
    # Validate mTLS attestation
    mtls_validation = parser.validate_mtls_attestation(
        enhanced_token,
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
        print(f"   Enhanced security facts:")
        for fact_type, fact_list in facts.items():
            if fact_list:
                values = [f.terms[0] if hasattr(f, 'terms') else str(f) for f in fact_list]
                print(f"      {fact_type}: {values}")
    
    # Step 5: Text-to-SQL conversion (if query provided)
    sql_query = None
    if user_query:
        print(f"\n🤖 Step 5: Text-to-SQL conversion with Claude API")
        print("-" * 40)
        try:
            sql_query = generate_sql_with_claude(user_query)
            print(f"✅ Generated SQL: {sql_query}")
        except Exception as e:
            print(f"❌ SQL generation failed: {e}")
            if not interactive:
                return False
    
    # Step 6: Server request with enhanced token
    step_num = 6 if user_query else 5
    print(f"\n🌐 Step {step_num}: Server request with enhanced token")
    print("-" * 40)
    if user_query and sql_query:
        print(f"   Natural language: \"{user_query}\"")
        print(f"   Generated SQL: {sql_query}\"")
    print(f"   Target endpoint: {endpoint}")
    
    try:
        import requests
        
        # Prepare request headers and data
        headers = {
            "Authorization": f"Bearer {enhanced_token}",
            "Content-Type": "application/json"
        }
        
        # If we have a SQL query, send as POST to query endpoint
        if sql_query and "/query" in endpoint:
            request_data = {
                "query": sql_query,
                "conn_id": "default",
                "natural_language_query": user_query
            }
            
            response = requests.post(
                f"https://localhost:8443{endpoint}",
                verify="certs/ca-cert.pem",
                cert=("certs/claude-client-cert.pem", "certs/claude-client-key.pem"),
                headers=headers,
                json=request_data,
                timeout=15
            )
        else:
            # Regular GET request
            response = requests.get(
                f"https://localhost:8443{endpoint}",
                verify="certs/ca-cert.pem",
                cert=("certs/claude-client-cert.pem", "certs/claude-client-key.pem"),
                headers=headers,
                timeout=10
            )
        
        print(f"   Response status: {response.status_code}")
        print(f"   Success: {'✅ YES' if response.status_code == 200 else '❌ NO'}")
        
        try:
            json_response = response.json()
            print(f"   Server validation result:")
            if "biscuit_validation" in json_response:
                biscuit_result = json_response["biscuit_validation"]
                print(f"      Token valid: {'✅' if biscuit_result.get('valid') else '❌'}")
                print(f"      User: {biscuit_result.get('primary_user', 'N/A')}")
                print(f"      Client verified: {'✅' if biscuit_result.get('client_identity_verified') else '❌'}")
                print(f"      Server verified: {'✅' if biscuit_result.get('server_identity_verified') else '❌'}")
            else:
                print("      No biscuit validation details in response")
        except:
            print(f"   Response text: {response.text}")
        
    except Exception as e:
        print(f"   Request failed: ❌ {e}")
        print("   Make sure the mTLS server is running:")
        print("   PYTHONPATH=. uv run python server/custom_mtls_server.py")
    
    # Summary
    print(f"\n📊 DEMONSTRATION SUMMARY")
    print("="*60)
    print(f"Base token creation: {'✅ SUCCESS' if base_token else '❌ FAILED'}")
    print(f"Enhanced token creation: {'✅ SUCCESS' if enhanced_token else '❌ FAILED'}")
    print(f"Local token validation: {'✅ SUCCESS' if token_valid else '❌ FAILED'}")
    print(f"Local mTLS validation: {'✅ SUCCESS' if mtls_valid else '❌ FAILED'}")
    
    overall_success = all([base_token, enhanced_token, token_valid, mtls_valid])
    print(f"\n🎯 OVERALL RESULT: {'✅ SUCCESS' if overall_success else '❌ FAILED'}")
    
    if overall_success:
        print("\n🎉 Enhanced security model demonstration completed successfully!")
        print("The system successfully:")
        print("  • Created a base Biscuit token with user credentials")
        print("  • Added an mTLS attestation block with identity verification")
        print("  • Validated both the token and mTLS attestation locally")
        print("  • Provided enhanced dual-layer security")
    else:
        print("\n⚠️  Some parts of the demonstration failed.")
        print("Review the output above for details.")
    
    return overall_success

def main():
    """Main demonstration entry point."""
    parser = argparse.ArgumentParser(description="Enhanced Security Demo with Text-to-SQL")
    parser.add_argument("--user", default="alice", help="User ID for token")
    parser.add_argument("--endpoint", default="/", help="Server endpoint to test")
    parser.add_argument("--query", "-q", help="Natural language query to convert to SQL and test")
    parser.add_argument("--interactive", "-i", action="store_true", 
                       help="Run in interactive mode for multiple queries")
    
    args = parser.parse_args()
    
    # Check for Claude API key if needed for text-to-SQL
    if (args.query or args.interactive):
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            print("❌ ANTHROPIC_API_KEY not found in environment or .env file")
            print("   Please add your Claude API key to the .env file:")
            print("   ANTHROPIC_API_KEY=your_api_key_here")
            return 1
        else:
            print(f"✅ Claude API key loaded: {api_key[:20]}...")
            print("")
    
    if args.interactive:
        # Run interactive mode
        interactive_text_to_sql_demo(args.user)
        return 0
    elif args.query:
        # Single query mode with text-to-SQL
        success = run_enhanced_security_demo(
            user_id=args.user,
            endpoint="/mcp/query",  # Use query endpoint for SQL
            user_query=args.query
        )
        return 0 if success else 1
    else:
        # Basic demo without text-to-SQL
        success = run_enhanced_security_demo(args.user, args.endpoint)
        return 0 if success else 1

if __name__ == "__main__":
    exit(main())