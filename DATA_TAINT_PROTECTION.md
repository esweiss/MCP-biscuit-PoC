# Data Taint Protection

## Overview

Data taint protection is a cryptographic information flow control mechanism that prevents data exfiltration by marking Biscuit tokens as "tainted" after they access sensitive data. This prevents the same token from being used to access internet-accessible services that could leak the data.

## Threat Model

**Attack Scenario**: A compromised AI agent or malicious actor attempts to:
1. Access sensitive patient data from the database
2. Send that data to an external service (e.g., via internet API, webhooks, or file uploads)

**Defense**: Data taint protection prevents this by:
- Automatically marking tokens as "tainted" after accessing sensitive data
- Rejecting tainted tokens when they attempt to access internet-facing services
- Providing cryptographic proof of data access that cannot be bypassed

## Architecture

### Dual mTLS Server Model

```
┌──────────────┐
│Claude Client │
│              │
└──────┬───────┘
       │ mTLS (claude-client cert)
   ┌───┴────┐
   │        │
   ▼        ▼
┌────────────┐  ┌───────────────┐
│ Database   │  │  HIPAA Server │
│ MCP Server │  │ (Internet API)│
│  :8443     │  │     :9443     │
└────────────┘  └───────────────┘
    │                   │
    │ Clean Token   → ✅ Accepted
    │ Tainted Token → 🔒 REJECTED
```

### Two Independent mTLS Servers

1. **Database MCP Server (port 8443)**
   - Handles database queries and patient data access
   - Automatically attenuates tokens after returning data
   - Adds `sensitive_data(1)` fact to tokens

2. **HIPAA MCP Server (port 9443)**
   - Provides HIPAA regulation lookup (internet-accessible)
   - Checks all tokens for `sensitive_data` fact
   - Rejects tainted tokens with HTTP 403 Forbidden

## Automatic Token Attenuation

### How It Works

When a database query returns patient data, the server **automatically** attenuates the Biscuit token:

**File**: `server/tools/query.py` (lines 147-189)

```python
# If data was fetched, attenuate the token with sensitive_data=1
# This prevents subsequent calls to internet-accessible tools
if query_results and len(query_results) > 0:
    logger.info(f"Query returned {len(query_results)} rows - attenuating token with sensitive_data=1")

    try:
        # Get public key and initialize parser
        public_key_hex = os.getenv('BISCUIT_PUBLIC_KEY')
        parser = BiscuitParser(public_key_hex)

        # Attenuate the token
        attenuation_result = parser.attenuate_with_sensitive_data(biscuit_token)

        if attenuation_result["status"] == "attenuated":
            attenuated_token = attenuation_result["attenuated_token"]
            logger.info(f"Token attenuated: {attenuation_result['original_block_count']} -> {attenuation_result['attenuated_block_count']} blocks")

            return {
                "data": query_results,
                "token": attenuated_token  # Return attenuated token
            }
```

### Token Lifecycle

```
1. Agent receives CLEAN token
   └─ Facts: patient_name("Erin oRTEga")

2. Agent sends token to Database MCP server
   └─ Calls: pg_query("SELECT * FROM patient_records WHERE name = 'Erin oRTEga'")

3. Database server executes query and returns data
   └─ Automatically attenuates token
   └─ Adds fact: sensitive_data(1)
   └─ Returns: { data: [...], token: <TAINTED_TOKEN> }

4. Agent now has TAINTED token
   └─ Facts: patient_name("Erin oRTEga"), sensitive_data(1)

5. Agent tries to call HIPAA server
   └─ Server checks for sensitive_data fact
   └─ REJECTS with 403 Forbidden
   └─ Data exfiltration prevented! 🔒
```

## Taint Checking

### HIPAA Server Implementation

**File**: `hipaa-server/custom_mtls_server.py` (lines 188-218)

```python
# Extract and validate Biscuit token if present (for data taint protection)
authorization_header = headers.get('authorization', '')
if authorization_header and authorization_header.startswith('Bearer '):
    biscuit_token = authorization_header[7:]  # Remove 'Bearer ' prefix

    # Check for data taint to prevent exfiltration
    if self.biscuit_parser:
        try:
            taint_check = self.biscuit_parser.check_sensitive_data(biscuit_token)

            if taint_check.get('is_tainted'):
                logger.warning(f"🚫 Token rejected: contains sensitive_data fact (data taint protection)")
                error_data = {
                    "error": "Token has been tainted with sensitive data",
                    "details": "Cannot access internet-accessible tools to prevent data exfiltration",
                    "status": "forbidden",
                    "tainted": True
                }
                await self.send_error_response(writer, 403, "Forbidden", error_data)
                return
            else:
                logger.info(f"✅ Token validated: no sensitive_data fact present")
```

### BiscuitParser Methods

**File**: `biscuit_parser_module.py`

```python
def check_sensitive_data(self, biscuit_token: str) -> dict:
    """
    Check if a Biscuit token contains the sensitive_data fact.

    Returns:
        dict: {
            'is_tainted': bool,
            'status': str,
            'sensitive_data_value': int (if tainted)
        }
    """

def attenuate_with_sensitive_data(self, biscuit_token: str, value: int = 1) -> dict:
    """
    Attenuate a Biscuit token by adding sensitive_data fact.

    Returns:
        dict: {
            'status': 'attenuated',
            'attenuated_token': str,
            'original_block_count': int,
            'attenuated_block_count': int
        }
    """
```

## Security Properties

### Cryptographic Enforcement

✅ **Non-Bypassable**: Token taint is cryptographically signed and cannot be removed
✅ **Stateless**: No server-side tracking required - proof is in the token itself
✅ **Tamper-Proof**: Any modification to remove the taint breaks the signature
✅ **Distributed**: Works across multiple independent services

### Defense-in-Depth Layers

1. **mTLS Transport Security**: Client certificate authentication
2. **Biscuit Token Verification**: Cryptographic signature validation
3. **Token Attenuation**: Automatic taint marking after data access
4. **Taint Checking**: Internet services reject tainted tokens
5. **PostgreSQL RLS**: Database-level row filtering
6. **Read-Only Enforcement**: All queries execute in read-only mode

## Demonstrations

### Quick Test

Start both servers:

```bash
# Terminal 1: Database MCP Server
source .env && PYTHONPATH=. BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
    uv run python server/custom_mtls_server.py

# Terminal 2: HIPAA MCP Server
source .env && PYTHONPATH=. BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
    uv run python hipaa-server/custom_mtls_server.py
```

Run demonstration:

```bash
# Comprehensive bash demo
./local/demo_data_exfiltration_protection.sh

# Python-based test
PYTHONPATH=. uv run python local/test_automatic_taint.py
```

### Expected Results

**Part 1**: Clean token accesses both servers successfully ✅

```bash
curl -k --cert certs/claude-client-cert.pem \
     --key certs/claude-client-key.pem \
     -H "Authorization: Bearer $CLEAN_TOKEN" \
     https://localhost:8443/
# Response: 200 OK

curl -k --cert certs/claude-client-cert.pem \
     --key certs/claude-client-key.pem \
     -H "Authorization: Bearer $CLEAN_TOKEN" \
     https://localhost:9443/
# Response: 200 OK
```

**Part 2**: Tainted token rejected by HIPAA server 🔒

```bash
# Token gets tainted after database query (automatic)
curl -k --cert certs/claude-client-cert.pem \
     --key certs/claude-client-key.pem \
     -H "Authorization: Bearer $TAINTED_TOKEN" \
     https://localhost:9443/
# Response: 403 Forbidden
# {
#   "error": "Token has been tainted with sensitive data",
#   "details": "Cannot access internet-accessible tools to prevent data exfiltration"
# }
```

## Main Demo Script Integration

The data taint protection is integrated into the main presentation demo:

**File**: `demo_magic_security.sh` (Demo 10)

```bash
# Demo 10: Data Taint Protection
function demo_data_taint_protection() {
    demo_section "DEMO 10: DUAL mTLS + DATA TAINT PROTECTION" \
        "Complete anti-exfiltration workflow with mTLS servers"

    pe "source .env && ./local/demo_data_exfiltration_protection.sh"
}
```

Run the complete presentation:

```bash
./demo_magic_security.sh
```

## Operational Notes

### Environment Variables Required

```bash
BISCUIT_PUBLIC_KEY=<hex_public_key>
BISCUIT_PRIVATE_KEY=<hex_private_key>  # Only for token generation
```

### Server Startup Order

1. Start Database MCP server first (port 8443)
2. Start HIPAA MCP server second (port 9443)
3. Both servers must use the same `BISCUIT_PUBLIC_KEY`

### Certificate Requirements

All client connections require:
- Client certificate signed by the project CA
- Client identity (`claude-client`) in authorized list
- Valid certificate chain

### Token Generation

Tokens are generated with patient-specific authorization:

```bash
uv run python utilities/biscuit_generator.py \
    --type custom \
    --user patient \
    --resource medical \
    --facts 'patient_name("Erin oRTEga")' \
    --show-public-key
```

### Token Verification

Verify token contents and taint status:

```bash
uv run python utilities/biscuit_parser_cli.py "$TOKEN" \
    --public-key "$PUBLIC_KEY" \
    --analyze
```

## Troubleshooting

### Token Rejection Issues

**Problem**: Clean tokens being rejected
- Check `BISCUIT_PUBLIC_KEY` matches between servers
- Verify token was generated with matching private key
- Check server logs for specific error messages

**Problem**: Tainted tokens being accepted
- Verify HIPAA server has `BISCUIT_PUBLIC_KEY` set
- Check server initialization logs for "🔐 Biscuit token validation enabled"
- Review `BiscuitParser` initialization in server code

### Server Connection Issues

**Problem**: 401 Unauthorized errors
- Verify client certificate exists and is valid
- Check client identity is in `authorized_clients` list
- Review mTLS handshake logs

**Problem**: 403 Forbidden errors
- Expected for tainted tokens on HIPAA server
- Unexpected for clean tokens - check token facts

### Token Attenuation Issues

**Problem**: Tokens not getting tainted
- Verify database query returned results (empty results = no taint)
- Check `server/tools/query.py` logs for attenuation messages
- Ensure `BISCUIT_PUBLIC_KEY` is set for database server

## Security Considerations

### When to Use Data Taint Protection

✅ **Use when**:
- Handling regulated data (HIPAA, GDPR, etc.)
- Preventing accidental data leakage
- Enforcing information flow policies
- Isolating sensitive from public services

⚠️ **Limitations**:
- Requires all services to check for taint
- Tokens become single-use after data access
- Need token refresh mechanism for continued work

### Best Practices

1. **Service Classification**: Clearly separate data-handling vs internet-facing services
2. **Token Lifecycle**: Implement token refresh for agents that need both capabilities
3. **Logging**: Monitor taint rejection events for security analysis
4. **Testing**: Validate taint protection in all deployment environments
5. **Documentation**: Ensure operators understand token lifecycle

## Related Documentation

- [SECURITY.md](SECURITY.md) - Complete security architecture
- [MTLS_IMPLEMENTATION.md](MTLS_IMPLEMENTATION.md) - mTLS technical details
- [README.md](README.md) - Project overview
- [SCRIPT.md](SCRIPT.md) - Setup guide

## References

- **Biscuit Token Specification**: https://github.com/biscuit-auth/biscuit
- **Information Flow Control**: Academic research on preventing data leakage
- **HIPAA Security Rule**: 45 CFR § 164.308 - Technical safeguards
