# MCP Biscuit Security Proof of Concept - Getting Started Guide

Welcome! This guide will walk you through running the MCP Biscuit security demonstration on your own system. It's a way to explore how biscuit tokens can provide cryptographic authorization for database access in an MCP server.

## What You'll Need

Before we start, make sure you have:
- **Python 3.13+** installed
- **A PostgreSQL database** pgAdmin4 highly recommended
- **An Anthropic API key** (for Claude integration)
- **uv package manager**

## Step 1: Get the Code

First, let's grab the repository and get everything set up:

```bash
git clone https://github.com/esweiss/MCP-biscuit-PoC.git
cd MCP-biscuit-PoC
```

## Step 2: Install Dependencies

Install all the required packages using uv:

```bash
uv sync
```
## Step 3: Configure The Database

You should see 2 files under "database", healthcare_data.sql and patients_user.sql .  Use these to set up postgres for the demo.

First, log into postgres with your admininstrator credentials,
Then run:
```bash
CREATE DATABASE healthcare_data;
```

Import the data with the command:
```bash
psql -U postgres -d healthcare_data -f database/healthcare_data.sql
```

Then add the unprivileged user:
```bash
psql -U postgres -f database/healthcare_data.sql
```

Finally. add the policy restricing row-level access to the healthcare_data table for the patients user:
```bash
psql -U postgres -f database/patient_data_policy.sql
```

## Step 4: Configure Your Environment

We need to set up your environment variables. There should be a `.env.example` file in the project - let's use that as our starting point:

```bash
# Copy the example file to create your .env
cp .env.example .env
```

Now open the `.env` file in your favorite text editor and fill in your actual values:

```bash
PG_MCP_URL=http://localhost:8000/sse
DATABASE_URL=postgresql://patients:patience@127.0.0.1:5432/healthcare_data
ANTHROPIC_API_KEY=your_actual_anthropic_api_key_here
BISCUIT_TOKEN=we'll_generate_this_next
BISCUIT_PUBLIC_KEY=we'll_generate_this_too
```

Don't worry about the biscuit token and public key yet - we'll generate those in the next step!

## Step 5: Generate Your Biscuit Token

This is where the magic happens! Let's create a biscuit token that contains a patient name:

```bash
uv run python utilities/biscuit_generator.py \
  --type custom \
  --user patient \
  --resource medical \
  --facts 'patient_name("Erin oRTEga")' \
  --show-public-key
```

You should see output like this:
```
Public Key: 8bc942e64ea187bd467a735b96f2f9d1ece68bdae29757cd2320bc5fea6ce42f
Custom Token: EpMBCikKDHBhdGllbnRfbmFtZQoLRXJpbiBvUlRFZ2EYAyIKCggIgAgSAxiBCBIkCAASIA7IsI...
```

Copy these values and update your `.env` file:
- Put the **Public Key** in `BISCUIT_PUBLIC_KEY`
- Put the **Custom Token** in `BISCUIT_TOKEN`

## Step 6: Start the MCP Server

Time to fire up the server! Open a terminal and run:

```bash
PYTHONPATH=. uv run python server/app.py
```

If everything is working, you should see:
```
2025-08-24 12:59:26.087409 INFO     Uvicorn running on http://0.0.0.0:8000
```

Great! Your server is now running and ready to accept requests.

## Step 7: Test Your Setup

Open a new terminal (keep the server running) and let's test it out:

```bash
# Query for the patient whose name is in our biscuit token
uv run python example-clients/claude_cli.py "Show me all database records for user Erin oRTEga"
```

If everything is set up correctly, you should see Claude generate a SQL query and return the database records for that patient!

## Step 8: Try a Different Patient

Let's see what happens when we query for a different patient:

```bash
uv run python example-clients/claude_cli.py "Show me all database records for user DAvID AndErSON"
```

## Step 9: Explore the Token

Want to peek inside your biscuit token? You can analyze it:

```bash
uv run python utilities/biscuit_parser_cli.py "YOUR_BISCUIT_TOKEN_HERE" \
  --public-key "YOUR_PUBLIC_KEY_HERE" \
  --analyze
```

This will show you the token's contents and verify its cryptographic signature.

## What's Happening Under the Hood

This demonstration shows how biscuit tokens work:

1. **Token Generation**: We created a token containing the fact `patient_name("Erin oRTEga")`
2. **Server Authentication**: The MCP server uses the token to verify requests
3. **Database Queries**: Claude generates SQL queries based on natural language
4. **Security Enforcement**: The biscuit token provides cryptographic proof of authorization

## Troubleshooting Tips

**Server won't start?**
- Make sure you're using `PYTHONPATH=. uv run python server/app.py`
- Check that all dependencies are installed

**API key errors?**
- Double-check your Anthropic API key in the `.env` file
- Make sure there are no extra spaces or quotes

**Database connection issues?**
- Verify your PostgreSQL server is running
- Check the DATABASE_URL format in your `.env` file

**Token verification fails?**
- This might be expected behavior if your database user has restricted privileges!

## Have Fun Exploring!

This proof of concept demonstrates how biscuit tokens can provide fine-grained, cryptographic authorization for database access. Try generating different tokens with various facts and rules to see how the system responds. Happy experimenting! 🚀
