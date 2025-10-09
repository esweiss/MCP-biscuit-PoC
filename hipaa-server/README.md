# HIPAA Regulations MCP Server

An MCP server for monitoring HIPAA regulations from the Electronic Code of Federal Regulations (eCFR) with Biscuit token authentication.

## Features

- **HIPAA Regulations Monitoring**: Fetches and monitors 45 CFR Title 45 (HIPAA regulations)
- **Change Detection**: Detects updates to regulations using content hashing
- **Biscuit Token Authentication**: Same security model as the database MCP server
- **Local Caching**: Stores regulations for faster access and comparison

## Setup

### 1. Configure Environment

Copy and edit the environment file:
```bash
cp hipaa-server/.env.example hipaa-server/.env
```

Use the same `BISCUIT_PUBLIC_KEY` as the database server.

### 2. Generate Token

```bash
uv run python utilities/biscuit_generator.py \
  --type custom \
  --user healthcare_admin \
  --resource hipaa_regulations \
  --facts 'user("healthcare_admin")' 'resource("hipaa_regulations")' \
  --show-public-key
```

### 3. Start Server

```bash
PYTHONPATH=. uv run python hipaa-server/app.py
```

Server runs on `http://localhost:8001` by default.

## Tools

### `check_hipaa_updates`

Checks for updates to HIPAA regulations.

**Parameters:**
- `biscuit_token`: Base64-encoded Biscuit token (required)

**Example Response:**
```json
{
  "success": true,
  "has_updates": false,
  "message": "No changes detected in HIPAA regulations (45 CFR Title 45)",
  "last_checked": "2025-10-09T17:00:00Z"
}
```

### `get_hipaa_structure`

Retrieves the structure of HIPAA regulations.

**Parameters:**
- `biscuit_token`: Base64-encoded Biscuit token (required)
- `section`: Optional section filter (e.g., "160" for Security Rule)

## eCFR API Source

Connects to: `https://www.ecfr.gov/api/versioner/v1/structure/2025-09-29/title-45.json`

This provides the complete 45 CFR structure including HIPAA Privacy, Security, and Breach Notification Rules.

## Cache

Regulations are cached in `hipaa-server/cache/`:
- `title-45.json`: Regulations data
- `metadata.json`: Hash and timestamp

Clear cache: `rm -rf hipaa-server/cache/*.json`

## Running Both Servers

```bash
# Terminal 1: Database Server (port 8000)
PYTHONPATH=. uv run python server/app.py

# Terminal 2: HIPAA Regulations Server (port 8001)
PYTHONPATH=. uv run python hipaa-server/app.py
```
