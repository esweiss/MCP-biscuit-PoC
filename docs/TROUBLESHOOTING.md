# Troubleshooting Guide

Comprehensive troubleshooting guide for the MCP Biscuit PoC project.

**For quick reference**, see the Top 10 Common Issues in `CLAUDE.md`.

---

## Biscuit Token Issues

### 1. Biscuit Keypair Mismatch in .env

**Problem**: Tokens generated with private key fail verification with public key

**Symptoms**:
- `'status': 'attenuation_error', 'error': 'No public key provided for token verification'`
- Token verification consistently fails
- Different error each time tokens are generated

**Root Cause**: `BISCUIT_PRIVATE_KEY` and `BISCUIT_PUBLIC_KEY` in `.env` were generated separately and are from different Ed25519 keypairs

**Solution**:
```python
# Generate new matching keypair
import biscuit_auth as biscuit
keypair = biscuit.KeyPair()
private_key = keypair.private_key.to_bytes().hex()
public_key = keypair.public_key.to_bytes().hex()

# Update .env file
BISCUIT_PRIVATE_KEY=<private_key>
BISCUIT_PUBLIC_KEY=<public_key>
```

**Verification**:
```python
from utilities.biscuit_generator import BiscuitGenerator
gen = BiscuitGenerator(private_key)
assert gen.get_public_key() == public_key  # Must be True
```

### 2. BiscuitGenerator Not Using Provided Private Key

**Problem**: `BiscuitGenerator(private_key_hex)` creates tokens with wrong keypair that can't be verified

**Root Cause**: Line 22 in `utilities/biscuit_generator.py` called `KeyPair()` constructor without using the provided private key, creating a new random keypair

**Solution**: Line 22 should be:
```python
self.keypair = biscuit.KeyPair.from_private_key(self.private_key)
```

**Impact**: Generator now creates tokens verifiable by `BiscuitParser` using matching public key from environment

### 3. biscuit-python 0.4.0 API Changes

**Problem 1**: `AttributeError: type object 'builtins.PublicKey' has no attribute 'from_hex'`

**Root Cause**: Misleading error message - actual issue is biscuit-python 0.4.0 removed `from_hex()` method

**Solution**:
```python
# OLD (0.3.2):
public_key = biscuit.PublicKey.from_hex(public_key_hex)

# NEW (0.4.0):
public_key_bytes = bytes.fromhex(public_key_hex)
public_key = biscuit.PublicKey.from_bytes(public_key_bytes, biscuit.Algorithm.Ed25519)
```

**Problem 2**: `TypeError: No constructor defined for Authorizer`

**Root Cause**: biscuit-python 0.4.0 changed Authorizer API to builder pattern

**Solution**:
```python
# OLD (0.3.2):
authorizer = biscuit.Authorizer(f"time({timestamp});")
authorizer.add_token(verified_token)

# NEW (0.4.0):
authorizer = biscuit.AuthorizerBuilder(f"time({timestamp});").build(verified_token)
```

### 4. Manual vs Automatic Token Tainting

**Problem**: Demo manually creates tainted tokens instead of showing automatic attenuation

**User Correction**: "The token should be tainted by its use in the database server, not in its creation"

**Solution**: Tokens are tainted by USE (accessing data), not by manual fact addition

**Correct Flow**:
```python
# Database server automatically attenuates after returning data
if query_results and len(query_results) > 0:
    attenuation_result = parser.attenuate_with_sensitive_data(biscuit_token)
    return {"data": query_results, "token": attenuated_token}
```

**Key Principle**: Tokens become tainted through **accessing sensitive data**, not manual creation

---

## mTLS Certificate Issues

### 5. Server Certificate Files Not Found

**Problem**: `Server certificate files not found in certs`

**Solution**: Run certificate generation scripts from project root:
```bash
cd certs
./create-ca.sh
./create-server-cert.sh
./create-client-cert.sh claude-client
```

**Verification**:
```bash
ls -la certs/ | grep -E '(ca-cert|server-cert|claude-client)'
```

### 6. ASGI Server mTLS Limitations

**Problem**: uvicorn/hypercorn don't provide client certificate access to middleware

**Root Cause**: ASGI specification doesn't define client certificate access mechanism

**Impact**: Standard ASGI middleware cannot implement identity-based client certificate validation

**Solution**: Use custom mTLS server with direct SSL transport access:
```bash
PYTHONPATH=. uv run python server/custom_mtls_server.py
```

### 7. Client Certificate Testing

**Problem**: Need to test unauthorized client rejection

**Solution**: Generate test certificates and run comprehensive test suite:
```bash
./certs/create-client-cert.sh unauthorized-hacker
uv run python local/test_mtls_comprehensive.py
```

**Expected Results**:
- Authorized client (`claude-client`): 200 OK
- Unauthorized client (`unauthorized-hacker`): 403 Forbidden

### 8. Multiple mTLS Servers on Different Ports

**Problem**: Need to run multiple mTLS servers simultaneously

**Solution**: Create separate server instances with different ports:
- Database: port 8443 (`server/custom_mtls_server.py`)
- HIPAA: port 9443 (`hipaa-server/custom_mtls_server.py`)

**Startup**:
```bash
# Terminal 1: Database server
source .env && PYTHONPATH=. BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
    uv run python server/custom_mtls_server.py

# Terminal 2: HIPAA server
source .env && PYTHONPATH=. BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
    uv run python hipaa-server/custom_mtls_server.py
```

---

## Environment and Dependency Issues

### 9. Import Errors

**Problem**: `ModuleNotFoundError: No module named 'server'`

**Root Cause**: Python can't find project modules

**Solution**: Always use `PYTHONPATH=.` prefix:
```bash
PYTHONPATH=. uv run python server/app.py
```

### 10. uv run Environment Variable Issues

**Problem**: Environment variables not passed to Python subprocesses via `uv run`

**Root Cause**: `uv run` creates isolated Python environment that doesn't inherit shell variables

**Solution**: Explicitly pass all required environment variables:
```bash
PYTHONPATH=. BISCUIT_PUBLIC_KEY=$KEY BISCUIT_TOKEN=$TOKEN uv run python script.py
```

**Test Scripts**: All test scripts must explicitly pass environment variables

### 11. Package Dependencies

**Problem**: `biscuit-auth` package not found

**Root Cause**: Package name confusion

**Solution**: Use `biscuit-python>=0.4.0` package instead:
```bash
uv add biscuit-python
```

**Import Pattern**: `import biscuit_auth as biscuit` works with `biscuit-python` package

### 12. Database Connection

**Problem**: Invalid DATABASE_URL with placeholder values

**Solution**: Use real connection string with actual credentials:
```bash
DATABASE_URL=postgresql://username:password@127.0.0.1:5432/healthcare_data
```

### 13. API Authentication

**Problem**: `invalid x-api-key` errors

**Solution**: Set real Anthropic API key in .env file:
```bash
ANTHROPIC_API_KEY=sk-ant-api03-...
```

---

## Testing and Validation Issues

### Testing Methodology ⚠️ CRITICAL

**NEVER declare a test successful without checking ALL outputs and error conditions**

#### Mandatory Testing Protocol

**1. Check ALL Background Process Outputs**
- Use `BashOutput` tool to read output from EVERY background bash process
- Look for processes with `status: failed` or non-zero exit codes
- Check for truncated outputs (indicates massive logging/errors)

**2. Search for Error Messages**
- Use `filter` parameter with `BashOutput` to find: `ERROR|Warning|Error|Exception|Failed|failed`
- Check both stdout and stderr for all processes
- Look for database connection errors, parameter errors, verification failures

**3. Verify Exit Codes**
- Exit code 0 = success
- Exit code 144 or other non-zero = failure
- Process `status: failed` means the test FAILED

**4. Examples of What to Look For**
- `Query execution error:`
- `'verification_failed', 'error':`
- `Error executing tool pg_query:`
- `unrecognized configuration parameter`
- `Connection lost`
- `Error forwarding request:`

#### What NOT to Do
❌ **Never assume success based only on client-side output**
❌ **Never ignore background server errors**
❌ **Never declare success without reading ALL process outputs**
❌ **Never skip checking exit codes and error logs**

#### Session 3 Learning Example
Client showed query results but server was actually failing with:
- Database parameter errors
- Biscuit token verification failures
- Query execution errors
- Multiple process failures (exit code 144)

**Lesson**: Client success ≠ server success - ALWAYS check both!

---

## Server Issues

### 14. Port Already in Use

**Problem**: `ERROR: address already in use`

**Diagnosis**:
```bash
# Check what's using the port
lsof -i :8443  # For database server
lsof -i :9443  # For HIPAA server
lsof -i :8000  # For backend MCP server
```

**Solution**:
```bash
# Kill existing processes
pkill -f 'server/custom_mtls_server.py'
pkill -f 'hipaa-server/custom_mtls_server.py'
pkill -f 'server/app.py'

# Wait for cleanup
sleep 2

# Restart servers
```

### 15. Server Logs Show Errors

**Problem**: Server starts but logs show errors

**Diagnosis**:
```bash
# Check database server logs
tail -50 /tmp/db_mtls.log

# Check HIPAA server logs
tail -50 /tmp/hipaa_mtls.log

# Check backend MCP server logs
tail -50 /tmp/backend_mcp_server.log
```

**Common Error Patterns**:
- `ERROR.*address already in use` → Port conflict (see #14)
- `No such file or directory.*certs` → Certificate issue (see #5)
- `BISCUIT_PUBLIC_KEY.*not set` → Environment variable issue (see #10)
- `ModuleNotFoundError` → PYTHONPATH issue (see #9)

---

## Data Taint Protection Issues

### 16. Tainted Tokens Not Being Rejected

**Problem**: HIPAA server accepts tainted tokens

**Diagnosis**:
```bash
# Check HIPAA server initialization
grep "Biscuit token validation enabled" /tmp/hipaa_mtls.log

# Check for taint rejection logs
grep "Token rejected.*sensitive_data" /tmp/hipaa_mtls.log
```

**Solution**:
1. Verify `BISCUIT_PUBLIC_KEY` is set for HIPAA server
2. Check server initialization logs for "🔐 Biscuit token validation enabled"
3. Review `BiscuitParser` initialization in `hipaa-server/custom_mtls_server.py:60-67`

### 17. Tokens Not Getting Tainted

**Problem**: Tokens remain clean after database queries

**Diagnosis**:
```bash
# Check database query logs
grep "attenuating token" /tmp/db_mtls.log

# Verify query returned results
grep "Query returned.*rows" /tmp/db_mtls.log
```

**Root Causes**:
1. Query returned no results (empty results = no taint)
2. `BISCUIT_PUBLIC_KEY` not set for database server
3. Automatic attenuation code not executing

**Solution**:
- Verify database query returned results: `len(query_results) > 0`
- Check `server/tools/query.py:147-189` logs for attenuation messages
- Ensure `BISCUIT_PUBLIC_KEY` environment variable is set

---

## Diagnostic Commands

### Quick Health Check
```bash
# Check all servers running
pgrep -f 'server/app.py' && echo "✅ Backend MCP server running"
pgrep -f 'server/custom_mtls_server.py' && echo "✅ Database mTLS server running"
pgrep -f 'hipaa-server/custom_mtls_server.py' && echo "✅ HIPAA mTLS server running"

# Test server connectivity
curl -k --cert certs/claude-client-cert.pem \
     --key certs/claude-client-key.pem \
     https://localhost:8443/health

curl -k --cert certs/claude-client-cert.pem \
     --key certs/claude-client-key.pem \
     https://localhost:9443/health
```

### Token Verification
```bash
# Verify token with public key
uv run python utilities/biscuit_parser_cli.py "$TOKEN" \
    --public-key "$PUBLIC_KEY" \
    --analyze

# Check for taint
PYTHONPATH=. uv run python -c "
from biscuit_parser_module import BiscuitParser
import os
parser = BiscuitParser(os.getenv('BISCUIT_PUBLIC_KEY'))
result = parser.check_sensitive_data(os.getenv('BISCUIT_TOKEN'))
print('Is tainted:', result.get('is_tainted', False))
"
```

### Environment Check
```bash
# Verify all required environment variables
source .env
echo "BISCUIT_PRIVATE_KEY length: ${#BISCUIT_PRIVATE_KEY}"
echo "BISCUIT_PUBLIC_KEY length: ${#BISCUIT_PUBLIC_KEY}"
echo "BISCUIT_TOKEN length: ${#BISCUIT_TOKEN}"
echo "DATABASE_URL set: $([ -n "$DATABASE_URL" ] && echo "✅" || echo "❌")"
echo "ANTHROPIC_API_KEY set: $([ -n "$ANTHROPIC_API_KEY" ] && echo "✅" || echo "❌")"
```

---

## Getting Help

### Log Files
- **Backend MCP Server**: `/tmp/backend_mcp_server.log`
- **Database mTLS Server**: `/tmp/db_mtls.log`
- **HIPAA mTLS Server**: `/tmp/hipaa_mtls.log`
- **mTLS Proxy Server**: `/tmp/mtls_server.log`

### Useful grep Patterns
```bash
# Find all errors
grep -i "error\|exception\|failed" /tmp/*.log

# Find security events
grep "Token.*rejected\|Token.*validated" /tmp/hipaa_mtls.log

# Find attenuation events
grep "attenuating token\|sensitive_data" /tmp/db_mtls.log
```

### Documentation References
- **Quick Reference**: `CLAUDE.md` (project root)
- **Session History**: `docs/SESSION_HISTORY.md`
- **Security Architecture**: `SECURITY.md`
- **mTLS Implementation**: `MTLS_IMPLEMENTATION.md`
- **Data Taint Protection**: `DATA_TAINT_PROTECTION.md`

---

**For additional help**, check the detailed session history in `docs/SESSION_HISTORY.md` or the quick reference in `CLAUDE.md`.
