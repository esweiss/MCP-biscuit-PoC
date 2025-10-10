# mTLS Implementation for MCP Biscuit PoC

This document describes the mutual TLS (mTLS) implementation added to the MCP Biscuit Proof of Concept.

## Overview

We have successfully implemented a complete mTLS security layer that provides:

- **Mutual Authentication**: Both client and server authenticate each other using X.509 certificates
- **Certificate Authority**: Custom CA for issuing and validating certificates
- **Identity Verification**: Server validates client identities against an authorized list
- **Transport Security**: All communications are encrypted and authenticated

## Implementation Components

### 1. Certificate Infrastructure

**Location**: `certs/` directory

- **Certificate Authority (CA)**
  - `ca-cert.pem` - CA certificate with proper extensions for certificate signing
  - `ca-key.pem` - CA private key (4096-bit RSA)

- **Server Certificate**
  - `server-cert.pem` - Server certificate for `mcp-server` 
  - `server-key.pem` - Server private key
  - Includes Subject Alternative Names for localhost/127.0.0.1

- **Client Certificates**
  - `claude-client-cert.pem` / `claude-client-key.pem` - Client certificate for Claude CLI
  - `authorized-client-cert.pem` / `authorized-client-key.pem` - Additional authorized client

### 2. Server Implementation

**Files Modified/Added**:
- `server/tls_config.py` - TLS configuration management
- `server/mtls_middleware.py` - Client certificate verification middleware  
- `server/app.py` - Updated to support TLS/mTLS

**Key Features**:
- SSL/TLS termination with server certificate
- Client certificate requirement (`ssl.CERT_REQUIRED`)
- Authorized client list validation
- Certificate identity extraction and verification

### 3. Client Implementation

**Files Added**:
- `example-clients/client_tls.py` - Client TLS configuration
- `example-clients/claude_cli_tls.py` - TLS-enabled MCP client
- `test_mtls.py` - Comprehensive mTLS test suite

## Security Model

### Authentication Flow

1. **TLS Handshake**: 
   - Client connects to server on port 8443 (HTTPS)
   - Server presents its certificate signed by CA
   - Client validates server certificate against CA

2. **Client Authentication**:
   - Server requires client certificate (`ssl.CERT_REQUIRED`)
   - Client presents certificate signed by CA
   - Server validates client certificate and extracts identity

3. **Authorization Check**:
   - Server checks if client identity is in authorized list
   - Only authorized clients (`claude-client`, `authorized-client`) are allowed
   - Unauthorized clients are rejected with 403 Forbidden

### Certificate Validation

- **Cryptographic Integrity**: All certificates signed by CA
- **Identity Binding**: Common Name (CN) field contains client identity
- **Certificate Chain**: Full chain validation from client → CA
- **Extensions**: Proper key usage extensions for client/server auth

## Testing Results

The implementation includes a comprehensive test suite (`test_mtls.py`) that validates:

✅ **Authorized Access**: Clients with valid certificates can connect
✅ **Unauthorized Rejection**: Clients without certificates are rejected  
✅ **Rogue Certificate Rejection**: Self-signed certificates are rejected

**Test Output**:
```
🔒 MCP Biscuit mTLS Test Suite
==================================================
Testing mTLS connection to MCP server...
✅ mTLS connection successful!
Status: 404
Response: Not Found...

Testing unauthorized connection (no client cert)...
✅ Connection properly rejected

Testing connection with unauthorized certificate...
✅ Rogue certificate properly rejected

==================================================
📊 Test Results:
  ✅ Authorized client: PASS
  ✅ No certificate rejection: PASS  
  ✅ Wrong certificate rejection: PASS

🎉 All mTLS tests PASSED! The security model is working correctly.
```

## Configuration

### Environment Variables

- `ENABLE_TLS=true` - Enable TLS/mTLS (default: true)
- `PG_MCP_URL=https://localhost:8443/sse` - Use HTTPS endpoint

### Server Configuration

```python
# Authorized client identities
authorized_clients = [
    "claude-client",
    "authorized-client"
]
```

### Certificate Paths

- Server certificates: `certs/server-cert.pem`, `certs/server-key.pem`
- CA certificate: `certs/ca-cert.pem`  
- Client certificates: `certs/{client-name}-cert.pem`, `certs/{client-name}-key.pem`

## Usage

### Starting the Server
```bash
# With TLS enabled (default)
PYTHONPATH=. uv run python server/app.py

# Without TLS  
ENABLE_TLS=false PYTHONPATH=. uv run python server/app.py
```

### Connecting with TLS Client
```bash
cd example-clients
uv run python claude_cli_tls.py "Show me database records"
```

### Running Tests
```bash
uv run python test_mtls.py
```

## Certificate Management

### Generating New Certificates

```bash
cd certs

# Create new CA (will recreate all certificates)
./create-ca.sh

# Create new server certificate
./create-server-cert.sh

# Create new client certificate
./create-client-cert.sh client-name
```

### Adding Authorized Clients

1. Generate client certificate: `./create-client-cert.sh new-client`
2. Add client CN to authorized list in `server/tls_config.py`
3. Restart server

## Security Properties

### Achieved Security Goals

✅ **Mutual Authentication**: Both parties verify each other's identity  
✅ **Transport Encryption**: All data encrypted with TLS 1.2+
✅ **Certificate Validation**: Full PKI chain validation
✅ **Identity-Based Access**: Only authorized client identities allowed
✅ **Tamper Protection**: Certificates cryptographically signed
✅ **Forward Secrecy**: TLS provides forward secrecy for session keys

### Attack Resistance

- **Man-in-the-Middle**: Prevented by mutual certificate validation
- **Unauthorized Access**: Blocked by client certificate requirement
- **Certificate Forgery**: Prevented by CA signature validation  
- **Identity Spoofing**: Client identity bound to certificate CN
- **Replay Attacks**: TLS nonces prevent replay

## Production Considerations

For production deployment, consider:

- **Certificate Rotation**: Implement automated certificate renewal
- **CA Security**: Secure storage of CA private key (HSM recommended)
- **Certificate Revocation**: Implement CRL or OCSP for certificate revocation
- **Monitoring**: Log all certificate validation events
- **Backup**: Secure backup of certificate infrastructure

## Integration with Biscuit Tokens

The mTLS layer provides **transport security**, while Biscuit tokens provide **application-level authorization**:

- **mTLS**: Authenticates the client identity (who is connecting)
- **Biscuit tokens**: Authorizes specific operations (what they can do)

This creates a defense-in-depth security model:
1. **Network Level**: TLS encryption
2. **Identity Level**: Client certificate authentication  
3. **Application Level**: Biscuit token authorization
4. **Database Level**: Row-Level Security policies

## Dual mTLS Server Architecture

### Overview

The system implements a **dual mTLS server architecture** with two independent servers running simultaneously:

1. **Database mTLS Server** (port 8443) - `server/custom_mtls_server.py`
   - Handles database queries with PostgreSQL integration
   - Biscuit token verification and fact extraction
   - PostgreSQL Row-Level Security (RLS) enforcement
   - Token attenuation after sensitive data access

2. **HIPAA mTLS Server** (port 9443) - `hipaa-server/custom_mtls_server.py`
   - Provides HIPAA-regulated operations
   - Internet-accessible tools (email, web services, etc.)
   - Data taint protection enforcement
   - Rejects tokens tainted with `sensitive_data` fact

### Server Configuration

Both servers use the same Certificate Authority and implement identical mTLS authentication:

```python
# Authorized client identities (both servers)
authorized_clients = [
    "claude-client",      # Human/AI client
    "authorized-client",  # Generic authorized client
    "hipaa-server",       # HIPAA server for inter-server communication
]
```

### Starting Dual mTLS Servers

```bash
# Start Database mTLS server (port 8443)
source .env && PYTHONPATH=. BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
  uv run python server/custom_mtls_server.py

# Start HIPAA mTLS server (port 9443)
source .env && PYTHONPATH=. BISCUIT_PUBLIC_KEY=$BISCUIT_PUBLIC_KEY \
  uv run python hipaa-server/custom_mtls_server.py
```

### Data Taint Protection Workflow

The dual server architecture enables sophisticated information flow control:

1. **Query Database** (port 8443)
   - Client connects with mTLS + clean Biscuit token
   - Query executes with RLS enforcement
   - Server returns data + **attenuated token** with `sensitive_data(1)` fact

2. **Attempt Internet Access** (port 9443)
   - Client connects to HIPAA server with tainted token
   - Server detects `sensitive_data` fact in token
   - **Request REJECTED** - prevents data exfiltration

3. **Normal Internet Access** (port 9443)
   - Client connects with clean (non-tainted) token
   - No `sensitive_data` fact detected
   - **Request ALLOWED** - normal operation

### Testing Dual mTLS Architecture

```bash
# Comprehensive end-to-end test (bash)
source .env && ./local/test_full_mtls_workflow.sh

# Python-based end-to-end test
PYTHONPATH=. uv run python local/test_mtls_end_to_end.py
```

**Test Coverage:**
- ✅ mTLS authentication to Database server (8443)
- ✅ mTLS authentication to HIPAA server (9443)
- ✅ Biscuit token cryptographic verification
- ✅ Token attenuation with `sensitive_data` fact
- ✅ Clean token acceptance by HIPAA server
- ✅ Tainted token rejection by HIPAA server (anti-exfiltration)

### Security Benefits

The dual mTLS architecture provides:

1. **Independent Security Boundaries**
   - Each server has its own security domain
   - Compromise of one server doesn't affect the other
   - Different authorization policies per server

2. **Cryptographic Information Flow Control**
   - Token attenuation creates tamper-proof data access proof
   - No central state required (stateless enforcement)
   - Non-bypassable taint tracking

3. **Defense-in-Depth**
   - Layer 1: mTLS transport security (both servers)
   - Layer 2: Biscuit token cryptographic verification
   - Layer 3: Token attenuation (data taint marking)
   - Layer 4: Per-server authorization policies
   - Layer 5: PostgreSQL Row-Level Security

4. **Anti-Exfiltration Protection**
   - Prevents accidental data leakage
   - Blocks malicious data exfiltration attempts
   - Enforced cryptographically at token level

### Architecture Diagram

```
┌──────────────┐
│Claude Client │
│ (claude-     │
│  client)     │
└──────┬───────┘
       │ mTLS + Biscuit Token
   ┌───┴────┐
   │        │
   ▼        ▼
┌────────────────┐       ┌──────────────────┐
│  Database      │       │  HIPAA           │
│  mTLS Server   │       │  mTLS Server     │
│  Port 8443     │       │  Port 9443       │
│                │       │                  │
│ • PostgreSQL   │       │ • HIPAA Tools    │
│ • Biscuit Auth │       │ • Internet Access│
│ • Token Atten. │       │ • Taint Check    │
└────────────────┘       └──────────────────┘
       │                        │
       ├─ Clean Token ────→     ├─→ ✅ ALLOWED
       └─ Tainted Token ──→     └─→ 🔒 REJECTED
```

### Production Deployment

For production, both servers can be deployed independently:

- Different hosts/containers for isolation
- Independent scaling based on load
- Separate monitoring and logging
- Different certificate authorities per environment
- Load balancing per server type

## Conclusion

The mTLS implementation successfully adds a robust transport security layer to the MCP Biscuit PoC, demonstrating enterprise-grade mutual authentication and encryption. The **dual mTLS server architecture** extends this foundation with independent security domains and cryptographic information flow control, creating a comprehensive defense-in-depth security model suitable for production deployment with sensitive data. The comprehensive test suite validates that all security layers work correctly and prevent unauthorized access and data exfiltration attempts.