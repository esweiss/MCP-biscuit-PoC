# MCP Biscuit Security Proof of Concept

A demonstration of **enhanced cryptographic authorization** using **Biscuit tokens** with **mTLS client certificates**, **Model Context Protocol (MCP)** servers, and **PostgreSQL Row-Level Security**.

## 🎯 What This Demonstrates

This proof of concept shows how **Biscuit tokens** combined with **mTLS client certificates** can provide enterprise-grade, cryptographically secure authorization for database access through MCP servers. Unlike traditional bearer tokens, this enhanced security model provides 4 layers of defense with transport security, token cryptography, database privileges, and row-level filtering.

### Key Features

- 🔐 **Enhanced mTLS + Biscuit Security**: 4-layer defense-in-depth architecture
- 🛡️ **Client Certificate Validation**: Identity-based access control with mTLS
- 🤖 **Interactive Text-to-SQL**: Natural language queries via Claude API integration
- 📊 **Healthcare Demo**: Simulated patient data access control scenario
- 🔍 **Comprehensive Testing**: Automated and manual security validation

## 🏗️ Enhanced Security Architecture

```
Client + mTLS Certificate + Enhanced Biscuit Token
         ↓
   mTLS Transport Security
         ↓
    Custom mTLS HTTP Server
         ↓
Client Certificate + Token Verification
         ↓
    MCP Server Integration
         ↓
PostgreSQL Database (RLS Policies)
         ↓
  Filtered Results Based on Token Facts
```

### 4-Layer Security Model

1. **mTLS Transport Layer**: Client certificate authentication and identity verification
2. **Cryptographic Token Layer**: Biscuit token signature verification and attestation validation
3. **Database Privilege Layer**: PostgreSQL user privileges and access controls
4. **Row-Level Security Layer**: Fine-grained data filtering based on token facts

### Components

- **Enhanced Biscuit Generator**: Creates tokens with mTLS attestation blocks
- **Custom mTLS Server**: Direct SSL certificate access with identity-based authorization
- **mTLS + Biscuit Validator**: Dual-layer security verification system
- **PostgreSQL Integration**: Row-Level Security policies for fine-grained access
- **Interactive Demo**: Text-to-SQL with Claude API integration

## 🚀 Quick Start

### Prerequisites
- Python 3.13+
- PostgreSQL database with pgAdmin4 (recommended)
- Anthropic API key
- uv package manager

### Setup
Follow the setup instructions in [SCRIPT.md]

## 📁 Project Structure

```
MCP-biscuit-PoC/
├── 📄 README.md                     # Project overview (this file)
├── 📄 SCRIPT.md                     # Step-by-step setup guide
├── 📄 SECURITY.md                   # Technical security deep dive
├── 📄 MTLS_IMPLEMENTATION.md        # mTLS technical documentation
├── 🎭 demo_magic_security.sh        # Main demo script for presentations
├── 🔧 pyproject.toml                # Python dependencies
├── 🔐 biscuit_parser_module.py      # Core biscuit token operations
├── 🛠️ utilities/                    # Token generation and parsing tools
├── 🖥️ server/                       # MCP server, mTLS proxy and implementation
├── 🔒 certs/                        # Certificate Authority and mTLS certificates
├── 👥 example-clients/              # Demo client applications
└── 💾 database/                     # Database setup scripts
```

### Key Files

- **`demo_magic_security.sh`**: Main interactive demo script for presentations
- **`biscuit_parser_module.py`**: Core Biscuit token parsing and validation
- **`utilities/biscuit_generator.py`**: Token generation with custom facts and rules
- **`server/app.py`**: Main MCP server with PostgreSQL integration
- **`server/mtls_proxy.py`**: mTLS proxy server for secure transport
- **`server/tools/query.py`**: Database query execution with Biscuit token authentication
- **`example-clients/claude_cli_tls.py`**: TLS-enabled MCP client with Claude API

## 🔐 Enhanced Security Model

### Enhanced Biscuit Token Structure
```
Enhanced Token = {
    Original Facts: [patient_name("Erin oRTEga")],
    mTLS Attestation: [
        mtls_client("claude-client"),
        mtls_audience("mcp-server"),  
        attestation_time(1234567890)
    ],
    Rules: [allow($user, $resource, $operation) <- ...],
    Checks: [
        check if user("alice"),
        check if mtls_client("claude-client"),
        check if mtls_audience("mcp-server")
    ],
    Signature: cryptographic_signature
}
```

### 4-Layer Defense in Depth
1. **mTLS Transport Security**: Client certificate authentication prevents unauthorized network access
2. **Cryptographic Token Verification**: Biscuit signatures prevent token tampering and ensure authenticity
3. **Database User Privileges**: Restricted PostgreSQL accounts limit system capabilities  
4. **Row-Level Security**: PostgreSQL policies filter data based on verified token context

### Enhanced Authorization Flow
1. Client connects with mTLS certificate + Enhanced Biscuit token
2. Server validates client certificate identity (transport layer)
3. Server verifies Biscuit token cryptographically (token layer)
4. Server validates mTLS attestation matches actual client identity (attestation layer)
5. Token facts extracted and applied as PostgreSQL session parameters (database layer)
6. Database RLS policies filter results based on verified session context
7. Only multiply-authorized data returned to client

## 🧪 Enhanced Testing Scenarios

### 🎯 Main Demo
```bash
# Start the comprehensive interactive security demo
./demo_magic_security.sh
```

### ✅ Individual Testing
```bash
# Test authorized access with Biscuit tokens
uv run python example-clients/claude_cli.py "Show me all medical records for patient Erin oRTEga"

# Test with TLS-enabled client
uv run python example-clients/claude_cli_tls.py "Show me all medical records for patient Erin oRTEga"
```

### 🔍 Token Analysis
```bash
# Inspect Biscuit tokens and their facts
uv run python utilities/biscuit_parser_cli.py TOKEN --public-key KEY --analyze
```

### 🖥️ Server Testing
```bash
# Start the MCP server
PYTHONPATH=. uv run python server/app.py

# Start the mTLS proxy server
PYTHONPATH=. uv run python server/mtls_proxy.py

# Test server endpoints with curl (requires client certificate)
curl -k --cert certs/claude-client-cert.pem --key certs/claude-client-key.pem \
     https://localhost:8443/sse
```

## 📚 Documentation

- **[SCRIPT.md](SCRIPT.md)**: Complete setup guide with step-by-step instructions
- **[SECURITY.md](SECURITY.md)**: Technical deep dive into the security architecture
- **[MTLS_IMPLEMENTATION.md](MTLS_IMPLEMENTATION.md)**: mTLS technical documentation and architecture
- **[PART3_TESTING_GUIDE.md](PART3_TESTING_GUIDE.md)**: Manual testing procedures and validation
- **Code Comments**: Inline documentation throughout the codebase

## 🎓 Educational Value

This PoC demonstrates several important concepts:

- **Enhanced Authorization**: Combining mTLS certificates with cryptographic tokens for multi-layer security
- **Defense-in-Depth Security**: 4 independent security layers that must all validate successfully
- **Zero-Trust Architecture**: Never trust, always verify at transport, token, database, and row levels
- **Certificate-Based Identity**: Using client certificates for cryptographically-verified identity
- **Cryptographic Attestation**: Tokens that prove specific client-server relationships
- **Database Security Integration**: Seamlessly combining application tokens with database-native security
- **AI Security**: Securing AI-powered natural language database queries with comprehensive access control

## 🛠️ Extending the Demo

### Enhanced mTLS Clients
```python
# Add new authorized client certificates
./certs/create-client-cert.sh new-client-name
# Update server/tls_config.py authorized_clients list
```

### Time-Based Token Expiration
```python
facts = ['patient_name("Erin oRTEga")', f'expiry({int(expiry.timestamp())})']
checks = ['check if time($time), expiry($exp), $time <= $exp']
```

### Role-Based Access Control with mTLS
```python
facts = ['user("alice")', 'role("nurse")', 'department("cardiology")',
         'mtls_client("nurse-workstation")', 'mtls_audience("mcp-server")']  
rules = ['allow($u, $r, "read") <- user($u), role("nurse"), resource($r)']
```

### Multi-Client Scenarios
```python
# Different client identities for testing
workstation_token = generator.add_mtls_attestation_block(token, "workstation-1", "mcp-server")
mobile_token = generator.add_mtls_attestation_block(token, "mobile-client", "mcp-server")
```

## 🤝 Contributing

This project demonstrates concepts for educational purposes. Feel free to:
- 🐛 Report issues or bugs
- 💡 Suggest improvements to the security model
- 📖 Improve documentation
- 🧪 Add new test scenarios

## 📄 License

See [LICENSE](LICENSE) file for details.

---

**Built with**: Python 3.13, FastMCP, PostgreSQL, Biscuit-python, Anthropic Claude API

**Demonstrates**: Enhanced mTLS + Biscuit security, Row-level security, Defense-in-depth architecture, Certificate-based identity, AI-powered secure database access
