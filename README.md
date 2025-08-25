# MCP Biscuit Security Proof of Concept

A demonstration of cryptographic authorization using **Biscuit tokens** with **Model Context Protocol (MCP)** servers and **PostgreSQL Row-Level Security**.

## 🎯 What This Demonstrates

This proof of concept shows how **Biscuit tokens** can provide fine-grained, cryptographically secure authorization for database access through an MCP server. Unlike traditional bearer tokens, Biscuit tokens contain embedded authorization logic that can be verified without server-side state.

### Key Features

- 🔐 **Cryptographic Authorization**: Biscuit tokens with embedded facts and rules
- 🛡️ **Multi-layered Security**: Token verification + PostgreSQL Row-Level Security  
- 🤖 **AI Integration**: Natural language queries via Claude API
- 📊 **Healthcare Demo**: Patient data access control scenario
- 🔍 **Token Analysis**: Tools to inspect and verify token contents

## 🏗️ Architecture

```
Client Request + Biscuit Token
         ↓
    MCP Server (FastMCP)
         ↓
 Token Verification & Fact Extraction
         ↓
PostgreSQL Database (RLS Policies)
         ↓
  Filtered Results Based on Token Facts
```

### Components

- **Biscuit Token Generator**: Creates tokens with custom facts/rules/checks
- **MCP Server**: FastMCP-based server with database tools and AI prompts
- **Token Parser**: Cryptographic verification and fact extraction
- **PostgreSQL Integration**: Row-Level Security policies for fine-grained access
- **Claude Integration**: Natural language to SQL query generation

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
├── 📄 README.md                 # This file
├── 📄 SCRIPT.md                 # Step-by-step setup guide  
├── 📄 SECURITY.md               # Technical security deep dive
├── 🔧 pyproject.toml            # Python dependencies
├── 🔐 biscuit_parser_module.py  # Core biscuit token operations
├── 🛠️ utilities/                # Token generation and parsing tools
├── 🖥️ server/                   # MCP server implementation  
├── 👥 example-clients/          # Demo client applications
└── 💾 database/                 # Database setup scripts
```

### Key Files

- **`biscuit_parser_module.py`**: Core Biscuit token parsing and verification
- **`utilities/biscuit_generator.py`**: Flexible token generation with custom facts
- **`server/app.py`**: Main MCP server with database tools and AI integration
- **`server/tools/query.py`**: Database query execution with token authentication
- **`example-clients/claude_cli.py`**: Demo client using Claude for natural language queries

## 🔐 Security Model

### Biscuit Token Structure
```
Token = {
    Facts: [patient_name("Erin oRTEga")],
    Rules: [allow($user, $resource, $operation) <- ...],
    Checks: [check if user("alice")],
    Signature: cryptographic_signature
}
```

### Defense in Depth
1. **Cryptographic Verification**: Tokens are signed and tamper-proof
2. **Database User Privileges**: Restricted database accounts limit capabilities  
3. **Row-Level Security**: PostgreSQL policies filter data based on token context
4. **Read-Only Transactions**: All queries executed in read-only mode

### Authorization Flow
1. Client sends query + Biscuit token
2. MCP server verifies token cryptographically 
3. Token facts extracted and applied as PostgreSQL session parameters
4. Database RLS policies filter results based on session context
5. Only authorized data returned to client

## 🧪 Testing Scenarios

### ✅ Authorized Access
```bash
# Token contains: patient_name("Erin oRTEga")
# Query returns: Records for Erin oRTEga only
uv run python example-clients/claude_cli.py "Show me records for Erin oRTEga"
```

### ❌ Privilege Escalation Prevention  
```bash
# Same token, different patient requested
# With RLS: Only returns Erin's data (ignores query for David)
# Without RLS: Returns all David's records
uv run python example-clients/claude_cli.py "Show me records for DAvID AndErSON" 
```

### 🔍 Token Analysis
```bash
# Inspect token contents and verify signature
uv run python utilities/biscuit_parser_cli.py TOKEN --public-key KEY --analyze
```

## 📚 Documentation

- **[SCRIPT.md](SCRIPT.md)**: Complete setup guide with step-by-step instructions
- **[SECURITY.md](SECURITY.md)**: Technical deep dive into the security architecture
- **Code Comments**: Inline documentation throughout the codebase

## 🎓 Educational Value

This PoC demonstrates several important concepts:

- **Modern Authorization**: Moving beyond simple bearer tokens to rich, embedded authorization logic
- **Cryptographic Security**: Using digital signatures for tamper-proof authorization
- **Zero-Trust Architecture**: Tokens contain all necessary authorization context
- **Database Security**: Integrating application-layer tokens with database-native security
- **AI Security**: Securing AI-powered database queries with fine-grained access control

## 🛠️ Extending the Demo

### Add Time-Based Expiration
```python
facts = ['patient_name("Erin oRTEga")', f'expiry({int(expiry.timestamp())})']
checks = ['check if time($time), expiry($exp), $time <= $exp']
```

### Role-Based Access Control
```python
facts = ['user("alice")', 'role("nurse")', 'department("cardiology")']  
rules = ['allow($u, $r, "read") <- user($u), role("nurse"), resource($r)']
```

### Resource Scoping
```python
facts = ['resource("patient_records")', 'operation("read")']
checks = ['check if resource("patient_records")', 'check if operation("read")']
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

**Built with**: Python 3.13, FastMCP, PostgreSQL, Biscuit-auth, Anthropic Claude API

**Demonstrates**: Cryptographic authorization, Row-level security, AI-powered database queries, Zero-trust architecture
