# CLAUDE.md - Project Memory and Learnings

This file captures key learnings, decisions, and context for future Claude Code sessions working on the MCP Biscuit PoC project.

## Project Overview

**MCP Biscuit Security Proof of Concept** - Demonstrates cryptographic authorization using Biscuit tokens with Model Context Protocol servers and PostgreSQL Row-Level Security.

**Repository**: https://github.com/esweiss/MCP-biscuit-PoC.git

## Key Accomplishments

### 1. Core Functionality Implemented
- ✅ **Biscuit Token Generation**: Added `create_custom_token()` method to `BiscuitGenerator` class
- ✅ **Token Parser Integration**: Fixed import paths in `biscuit_parser_cli.py` 
- ✅ **MCP Server**: Running FastMCP server with PostgreSQL integration
- ✅ **Claude Integration**: Natural language to SQL query generation via `claude_cli.py`
- ✅ **Security Enforcement**: Multi-layered authorization with token verification + database RLS

### 2. Dependencies and Environment
- **Key Dependency**: `biscuit-python>=0.3.2` (NOT `biscuit-auth` - that package doesn't exist)
- **Python Version**: 3.13+ required
- **Package Manager**: Uses `uv` (not pip)
- **Import Pattern**: `import biscuit_auth as biscuit` works with `biscuit-python` package

### 3. Security Architecture
- **Layer 1**: Cryptographic token verification using Biscuit signatures
- **Layer 2**: PostgreSQL user privilege enforcement (`postgres` vs `patients` users)  
- **Layer 3**: Row-Level Security policies filtering data based on token facts
- **Read-Only**: All database queries execute in `SET TRANSACTION READ ONLY` mode

### 4. Testing Results
- **Admin User (`postgres`)**: Can set configuration parameters, bypasses RLS
- **Restricted User (`patients`)**: Cannot set config parameters, subject to RLS policies
- **Token with `patient_name("Erin oRTEga")`**: Successfully retrieves records for that patient
- **Privilege Escalation Prevention**: Restricted user gets config parameter errors (expected behavior)

## File Structure and Key Components

```
MCP-biscuit-PoC/
├── biscuit_parser_module.py     # Core Biscuit operations - DO NOT MODIFY
├── utilities/
│   ├── biscuit_generator.py     # Token generation - ADDED create_custom_token()
│   └── biscuit_parser_cli.py    # CLI parser - FIXED import paths
├── server/
│   ├── app.py                   # Main MCP server
│   └── tools/query.py           # Database query execution with token auth
├── example-clients/
│   └── claude_cli.py           # Demo client using Claude API
├── .env                        # Environment config (contains real credentials)
├── README.md                   # Project overview and quick start
├── SCRIPT.md                   # Step-by-step setup guide  
└── SECURITY.md                 # Technical security deep dive
```

## Critical Implementation Details

### Custom Token Generation
**Location**: `utilities/biscuit_generator.py:138-167`
```python
def create_custom_token(self, facts: List[str], rules: Optional[List[str]] = None, 
                      checks: Optional[List[str]] = None) -> str:
    # Allows arbitrary facts like 'patient_name("Erin oRTEga")'
    # Also supports custom rules and checks
```

### Token Authentication Flow
**Location**: `server/tools/query.py:53-68`
```python
def authenticate_token(biscuit_token: str):
    # 1. Get public key from environment
    # 2. Initialize BiscuitParser with public key
    # 3. Call verify_and_extract_facts() 
    # 4. Return facts for database session context
```

### Server Startup Command
**IMPORTANT**: Must use `PYTHONPATH=. uv run python server/app.py`
- Without `PYTHONPATH=.` the server fails with import errors
- Server runs on `http://0.0.0.0:8000` with SSE transport

## Environment Configuration

### .env File Structure
```bash
PG_MCP_URL=http://localhost:8000/sse
DATABASE_URL=postgresql://username:password@127.0.0.1:5432/healthcare_data
ANTHROPIC_API_KEY=sk-ant-api03-...
BISCUIT_TOKEN=EpMBCikKDHBhdGllbnRfbmFtZQ...
BISCUIT_PUBLIC_KEY=8bc942e64ea187bd467a735b96f2f9d1...
```

### Test Data
- Database contains healthcare records with patients like "Erin oRTEga" and "DAvID AndErSON"
- Case-insensitive matching works (Claude generates appropriate SQL)
- Patient names have mixed case to test matching logic

## Testing Patterns

### Successful Token Generation
```bash
uv run python utilities/biscuit_generator.py \
  --type custom \
  --user patient \
  --resource medical \
  --facts 'patient_name("Erin oRTEga")' \
  --show-public-key
```

### Query Testing
```bash
# Test authorized access
uv run python example-clients/claude_cli.py "Show me all database records for user Erin oRTEga"

# Test different patient  
uv run python example-clients/claude_cli.py "Show me all database records for user DAvID AndErSON"
```

### Token Analysis
```bash
uv run python utilities/biscuit_parser_cli.py "TOKEN_HERE" \
  --public-key "PUBLIC_KEY_HERE" \
  --analyze
```

## Common Issues and Solutions

### 1. Import Errors
**Problem**: `ModuleNotFoundError: No module named 'server'`
**Solution**: Use `PYTHONPATH=. uv run python server/app.py`

### 2. Database Connection
**Problem**: Invalid DATABASE_URL with placeholder values
**Solution**: Use real connection string with actual credentials

### 3. API Authentication
**Problem**: `invalid x-api-key` errors
**Solution**: Set real Anthropic API key in .env file

### 4. Package Dependencies
**Problem**: `biscuit-auth` package not found
**Solution**: Use `biscuit-python` package instead

## Security Observations

### Expected Behaviors
- **Admin user**: All queries work, RLS policies bypassed
- **Restricted user**: Config parameter errors are EXPECTED and demonstrate security boundaries
- **Token verification**: Cryptographic signatures prevent tampering
- **Row filtering**: RLS policies should filter data based on token facts (when user has privileges)

### Security Boundaries
1. **Token tampering**: Any modification breaks cryptographic signature
2. **Database privileges**: Restricted users cannot set arbitrary config parameters
3. **Read-only enforcement**: All queries run in read-only transactions
4. **Fact-based filtering**: Token facts become database session context

## Documentation Created

- **README.md**: Project overview, quick start, architecture
- **SCRIPT.md**: Step-by-step setup guide with database configuration
- **SECURITY.md**: Technical deep dive into multi-layered security model
- **CLAUDE.md**: This file - project memory and learnings

## Next Session Priorities

1. **Database Setup**: The SCRIPT.md references database files that may not exist yet
2. **Row-Level Security**: Implement actual RLS policies in PostgreSQL 
3. **Token-to-Database Integration**: Complete the fact extraction to session parameter mapping
4. **Error Handling**: Improve error messages and edge case handling
5. **Testing**: Create comprehensive test suite for different authorization scenarios

## Development Environment Notes

- **Python**: 3.13+ required (project uses modern Python features)
- **Package Manager**: uv only (no pip references per user request)
- **Database**: PostgreSQL with pgAdmin4 recommended
- **IDE**: Works well with modern editors supporting Python 3.13+

## User Preferences Observed

- Prefers `uv` over `pip` 
- Wants friendly, approachable documentation
- Values comprehensive security explanations
- Likes step-by-step guides over high-level overviews
- Requests removal of unnecessary complexity (removed multi-patient and time-based examples)

---

*This file should be updated by future Claude Code sessions to maintain project continuity and capture new learnings.*