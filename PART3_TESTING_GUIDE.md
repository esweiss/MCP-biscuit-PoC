# Enhanced mTLS + Biscuit Security Manual Testing Guide

This guide provides step-by-step instructions for manually testing the enhanced security model that combines mTLS client certificates with Biscuit token authorization.

## Overview

The enhanced security model provides **defense-in-depth** with four validation layers:

1. **mTLS Transport Security**: Client certificate authentication
2. **Biscuit Cryptographic Security**: Token signature verification  
3. **Identity Consistency**: Client certificate identity must match token
4. **Audience Validation**: Token must be intended for this specific server

## Prerequisites

### 1. Environment Setup

First, ensure your environment is properly configured:

```bash
# Run the setup script
uv run python setup_enhanced_security_demo.py

# Verify certificates exist
ls -la certs/
# Should show: ca-cert.pem, server-cert.pem, server-key.pem, claude-client-cert.pem, claude-client-key.pem

# Load environment variables
source .env

# Verify Biscuit keys are available
echo "Public Key: $BISCUIT_PUBLIC_KEY"
```

### 2. Start the mTLS Server

In one terminal, start the enhanced mTLS server:

```bash
# Start server with Biscuit validation enabled
BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY PYTHONPATH=. uv run python server/custom_mtls_server.py
```

You should see:
```
🔐 Biscuit token validation enabled
✅ Custom mTLS HTTP Server running on https://0.0.0.0:8443
🔐 Client certificate verification: ENABLED
```

## Test Scenario 1: Interactive Text-to-SQL with Enhanced Security

This test demonstrates the complete enhanced security flow with text-to-SQL conversion using Claude API.

### Prerequisites for Text-to-SQL Testing

```bash
# Ensure Claude API key is set
export ANTHROPIC_API_KEY=your_api_key_here

# Verify API key is available
echo "Claude API key: ${ANTHROPIC_API_KEY:0:20}..."
```

### Step 1: Interactive Text-to-SQL Demo

```bash
# Run interactive text-to-SQL demo with enhanced security
BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
uv run python demo_enhanced_security.py --user alice --interactive
```

**Interactive Commands to Try:**
```
🔍 Enter your query: show me all patients
🔍 Enter your query: find patients with diabetes  
🔍 Enter your query: list recent appointments
🔍 Enter your query: show medical records for Erin
🔍 Enter your query: count total patients
🔍 Enter your query: help
🔍 Enter your query: quit
```

**Expected Results**: 
- ✅ Natural language converted to SQL using Claude API
- ✅ Enhanced security token created and validated
- ✅ SQL query sent with enhanced mTLS + Biscuit security
- ✅ Complete security validation flow demonstrated

### Step 2: Single Query Test

```bash
# Test single query with text-to-SQL conversion
BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
uv run python demo_enhanced_security.py --user alice --query "show me all patients with diabetes"
```

**Expected Result**: 
- ✅ Text converted to SQL: `SELECT * FROM patients WHERE LOWER(condition) LIKE '%diabetes%' LIMIT 10;`
- ✅ Enhanced security validation passes
- ✅ SQL query sent to server with enhanced authentication

### Step 3: Basic Demo (Without Text-to-SQL)

```bash
# Run basic enhanced security demo without text-to-SQL
BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
uv run python demo_enhanced_security.py --user alice --endpoint /
```

**Expected Result**: ✅ Enhanced token validation passes and establishes secure connection to server.

## Test Scenario 2: Wrong Client Identity (Should Fail)

This test verifies that tokens with incorrect client identity are rejected.

### Manual Test Steps

```bash
# Test wrong client identity rejection
BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
uv run python test_wrong_client_identity.py
```

**Expected Results**: 
- ✅ Local validation should FAIL (expected)
- ✅ Server should return 403 Forbidden
- ✅ Error message: "Expected client 'claude-client' not found in token"

### Manual Verification Steps

1. **Check Local Validation**:
   ```bash
   # Create token with wrong client identity manually
   python -c "
   from utilities.biscuit_generator import BiscuitGenerator
   from biscuit_parser_module import BiscuitParser
   import os
   
   generator = BiscuitGenerator(os.getenv('BISCUIT_PRIVATE_KEY'))
   parser = BiscuitParser(os.getenv('BISCUIT_PUBLIC_KEY'))
   
   # Create base token
   base_token = generator.create_custom_token(['user(\"alice\")'])
   
   # Add wrong client identity
   enhanced_token = generator.add_mtls_attestation_block(
       base_token, 'fake-client', 'mcp-server', 
       public_key_hex=os.getenv('BISCUIT_PUBLIC_KEY')
   )
   
   # Validate (should fail)
   result = parser.validate_mtls_attestation(enhanced_token, 'claude-client', 'mcp-server')
   print(f'Validation result: {result.get(\"mtls_validation\")}')
   if not result.get('mtls_validation'):
       print('✅ PASS: Wrong client identity correctly rejected')
       for key, value in result.get('validation_details', {}).items():
           if '_error' in key:
               print(f'   {key}: {value}')
   "
   ```

2. **Verify Server Rejection**:
   - Check server logs for "❌ Biscuit token validation failed"
   - Confirm HTTP 403 response

## Test Scenario 3: Wrong Server Audience (Should Fail)

This test verifies that tokens intended for other servers are rejected.

### Manual Test Steps

```bash
# Test wrong server audience rejection
BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
uv run python test_wrong_audience.py
```

**Expected Results**:
- ✅ Local validation should FAIL (expected)
- ✅ Server should return 403 Forbidden
- ✅ Error message: "Expected server audience 'mcp-server' not found in token"

### Manual Verification Steps

```bash
# Create token with wrong audience manually
python -c "
from utilities.biscuit_generator import BiscuitGenerator
from biscuit_parser_module import BiscuitParser
import os

generator = BiscuitGenerator(os.getenv('BISCUIT_PRIVATE_KEY'))
parser = BiscuitParser(os.getenv('BISCUIT_PUBLIC_KEY'))

# Create base token
base_token = generator.create_custom_token(['user(\"alice\")'])

# Add wrong server audience
enhanced_token = generator.add_mtls_attestation_block(
    base_token, 'claude-client', 'wrong-server',  # Wrong audience!
    public_key_hex=os.getenv('BISCUIT_PUBLIC_KEY')
)

# Validate (should fail)
result = parser.validate_mtls_attestation(enhanced_token, 'claude-client', 'mcp-server')
print(f'Validation result: {result.get(\"mtls_validation\")}')
if not result.get('mtls_validation'):
    print('✅ PASS: Wrong server audience correctly rejected')
    for key, value in result.get('validation_details', {}).items():
        if '_error' in key:
            print(f'   {key}: {value}')
"
```

## Test Scenario 4: User Authorization Testing

This test demonstrates the separation between transport security and business logic authorization.

### Manual Test Steps

```bash
# Test user identity handling
BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
uv run python test_wrong_user_identity.py
```

**Expected Results**:
- ✅ Token verification should PASS (cryptographically valid)
- ✅ mTLS attestation should PASS (identities are correct)
- 🔍 Server response depends on business logic implementation

### Manual Step-by-Step Verification

1. **Create Token for Different User**:
   ```bash
   # Create token for user "eve" instead of authorized "alice"
   EVE_TOKEN=$(BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY uv run python utilities/biscuit_generator.py \
       --type custom \
       --facts 'user("eve")' 'resource("medical_records")' 'patient_name("Erin oRTEga")' \
       --private-key $BISCUIT_PRIVATE_KEY)
   
   echo "Token for user 'eve' created: ${EVE_TOKEN:0:50}..."
   ```

2. **Add Correct mTLS Attestation**:
   ```bash
   # Test that mTLS validation passes but user might be unauthorized
   python -c "
   from utilities.biscuit_generator import BiscuitGenerator
   from biscuit_parser_module import BiscuitParser
   import os
   
   generator = BiscuitGenerator(os.getenv('BISCUIT_PRIVATE_KEY'))
   parser = BiscuitParser(os.getenv('BISCUIT_PUBLIC_KEY'))
   
   # Create token for eve
   base_token = generator.create_custom_token(['user(\"eve\")', 'resource(\"medical_records\")'])
   
   # Add CORRECT mTLS attestation 
   enhanced_token = generator.add_mtls_attestation_block(
       base_token, 'claude-client', 'mcp-server',  # Correct identities
       public_key_hex=os.getenv('BISCUIT_PUBLIC_KEY')
   )
   
   # Validate mTLS (should pass)
   mtls_result = parser.validate_mtls_attestation(enhanced_token, 'claude-client', 'mcp-server')
   print(f'mTLS validation: {\"✅ PASS\" if mtls_result.get(\"mtls_validation\") else \"❌ FAIL\"}')
   
   # Extract user info
   facts_result = parser.verify_and_extract_facts(enhanced_token)
   facts = facts_result.get('facts', {})
   print(f'Token facts extracted successfully: {facts_result.get(\"status\") == \"verified_with_facts\"}')
   
   print('\\n💡 Key Point: mTLS validation passes (transport security) but business logic may reject user \"eve\"')
   "
   ```

## Manual Token Analysis

### Inspect Token Structure

```bash
# Analyze any token structure manually
python -c "
from biscuit_parser_module import BiscuitParser
import os

# Replace TOKEN_HERE with actual token
TOKEN = 'EoECCpYBCgttdGxzX2NsaWVudAoNY2xhdWRlLWNsaWVudAoNbXRsc19hdWRpZW5jZQoKbWNwLXNlcnZlchBhdHRlc3RhdGlvbl90aW1lGAM...'

parser = BiscuitParser(os.getenv('BISCUIT_PUBLIC_KEY'))

# Parse without verification to see structure
unverified = parser.parse_unverified(TOKEN)
print('Token structure:')
for key, value in unverified.items():
    print(f'  {key}: {value}')

# Parse with verification to extract facts
verified = parser.verify_and_extract_facts(TOKEN)
if verified.get('status') == 'verified_with_facts':
    facts = verified.get('facts', {})
    print('\\nExtracted facts:')
    for fact_type, fact_list in facts.items():
        if fact_list:
            print(f'  {fact_type}: {fact_list}')
"
```

### Manual mTLS Validation

```bash
# Test mTLS validation with custom parameters
python -c "
from biscuit_parser_module import BiscuitParser
import os

parser = BiscuitParser(os.getenv('BISCUIT_PUBLIC_KEY'))

# Replace with your token and test different identities
TOKEN = 'YOUR_TOKEN_HERE'
CLIENT_IDENTITY = 'claude-client'  # Change this to test different clients
SERVER_IDENTITY = 'mcp-server'     # Change this to test different servers

result = parser.validate_mtls_attestation(TOKEN, CLIENT_IDENTITY, SERVER_IDENTITY)

print(f'mTLS Validation Result: {\"✅ PASS\" if result.get(\"mtls_validation\") else \"❌ FAIL\"}')
print(f'Status: {result.get(\"status\")}')
print(f'Expected client: {result.get(\"expected_client\")}')
print(f'Expected server: {result.get(\"expected_server\")}')
print(f'Found clients: {result.get(\"found_clients\")}')
print(f'Found audiences: {result.get(\"found_audiences\")}')

if not result.get('mtls_validation'):
    print('\\nValidation Errors:')
    details = result.get('validation_details', {})
    for key, value in details.items():
        if '_error' in key:
            print(f'  {key}: {value}')
"
```

## Comprehensive Test Run

To run all tests automatically:

```bash
# Run the complete test suite
BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
uv run python run_all_security_tests.py
```

## Troubleshooting

### Common Issues

1. **Server Connection Refused**
   ```bash
   # Check if server is running
   curl -k https://localhost:8443/health
   # Should get connection (may fail with cert error, that's expected)
   ```

2. **Biscuit Validation Disabled**
   - Ensure `BISCUIT_PUBLIC_KEY` environment variable is set
   - Server logs should show "🔐 Biscuit token validation enabled"

3. **Certificate Issues**
   ```bash
   # Verify certificates exist and are readable
   openssl x509 -in certs/claude-client-cert.pem -text -noout | grep "Subject:"
   # Should show: Subject: CN = claude-client
   ```

4. **Token Format Issues**
   ```bash
   # Verify token is valid base64
   python -c "
   import base64
   token = 'YOUR_TOKEN_HERE'
   try:
       decoded = base64.b64decode(token)
       print(f'✅ Token is valid base64 ({len(decoded)} bytes)')
   except Exception as e:
       print(f'❌ Token base64 error: {e}')
   "
   ```

### Debug Mode

For detailed debugging, add debug prints:

```bash
# Run with detailed output
BISCUIT_PRIVATE_KEY=$BISCUIT_PRIVATE_KEY BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
python -c "
import os
os.environ['DEBUG'] = '1'
# Run your test here with detailed logging
"
```

## Security Verification Checklist

Use this checklist to verify the enhanced security model:

- [ ] **mTLS Layer**
  - [ ] Client certificate authentication working
  - [ ] Unauthorized certificates rejected
  - [ ] Client identity extracted correctly

- [ ] **Biscuit Token Layer** 
  - [ ] Token cryptographic verification working
  - [ ] Invalid signatures rejected
  - [ ] Facts extracted correctly

- [ ] **Identity Consistency Layer**
  - [ ] Client cert identity matches token `mtls_client` fact
  - [ ] Mismatched client identities rejected
  - [ ] Server audience validation working
  - [ ] Wrong audiences rejected

- [ ] **Attestation Layer**
  - [ ] Attestation timestamps validated
  - [ ] Expired attestations rejected (>1 hour)

- [ ] **Integration Testing**
  - [ ] Valid enhanced tokens accepted
  - [ ] Invalid enhanced tokens rejected
  - [ ] Proper error messages returned
  - [ ] Security boundaries maintained

## Expected Test Results Summary

| Test Scenario | Text-to-SQL | Local Validation | Server Response | Security Status |
|---------------|-------------|------------------|-----------------|-----------------|
| ✅ Valid enhanced token with query | SUCCESS | PASS | 200/403* | ✅ SECURE |
| ✅ Valid enhanced token (basic) | N/A | PASS | 200/403* | ✅ SECURE |
| ❌ Wrong client identity | SUCCESS | FAIL | 403 | ✅ SECURE |
| ❌ Wrong server audience | SUCCESS | FAIL | 403 | ✅ SECURE |
| 👤 Wrong user identity | SUCCESS | PASS** | 403* | ✅ SECURE |

*Server response may be 403 if business logic rejects the user or if full MCP integration isn't complete
**mTLS validation passes, but user authorization is application-dependent

### Text-to-SQL Flow Security

The enhanced demo now includes a complete text-to-SQL security flow:

1. **Natural Language Input**: User enters queries like "show me all patients"
2. **Claude API Conversion**: Text converted to safe SQL using Claude API
3. **Enhanced Security Token**: mTLS + Biscuit token created with user and server identities
4. **Secure Transmission**: SQL query sent with enhanced authentication
5. **Multi-Layer Validation**: Server validates all security layers before execution

## Conclusion

This manual testing guide demonstrates that the enhanced mTLS + Biscuit security model provides comprehensive **defense-in-depth** protection with multiple independent validation layers. Each layer can be tested individually to verify proper security enforcement.

The system successfully:
- ✅ Authenticates clients using mTLS certificates
- ✅ Validates cryptographic token integrity  
- ✅ Enforces identity consistency between transport and authorization layers
- ✅ Validates server audience to prevent token misuse
- ✅ Maintains separation between transport security and business logic

For questions or issues, refer to the project documentation or create an issue in the repository.