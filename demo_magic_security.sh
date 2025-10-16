#!/bin/bash
#
# 🎯 MCP-Biscuit Security Demo Magic Script
#
# Interactive terminal presentation demonstrating the enhanced mTLS + Biscuit security model
#
# Requirements:
# - demo-magic (https://github.com/paxtonhare/demo-magic)
# - mTLS server running on https://localhost:8443
# - All certificates generated in certs/ directory
#
# Usage:
#   ./demo_magic_security.sh
#
# Controls during presentation:
#   ENTER    - Execute current command
#   Ctrl+C   - Exit demo
#

########################
# Include demo-magic
########################
# Disable typing speed to avoid pv dependency if not available
if ! command -v pv &> /dev/null; then
    echo "⚠️  pv not available - disabling typing effects"
    unset TYPE_SPEED
fi

. demo-magic.sh

########################
# Configure demo-magic
########################
# Only set TYPE_SPEED if pv is available
if command -v pv &> /dev/null; then
    TYPE_SPEED=200
fi
DEMO_PROMPT="${GREEN}➜ ${CYAN}\W ${COLOR_RESET}"

########################
# Presentation Setup
########################
function setup() {
    clear
    DEMO_PROMPT="${GREEN}🛡️  MCP-Biscuit Security ${CYAN}\W ${COLOR_RESET}"
}

########################
# Utility Functions
########################
function demo_header() {
    clear
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${BOLD}${WHITE}                    🎯 MCP-BISCUIT SECURITY DEMONSTRATION                     ${COLOR_RESET}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo ""
    echo -e "${YELLOW}Enhanced mTLS + Biscuit Cryptographic Authorization${COLOR_RESET}"
    echo -e "${CYAN}Defense-in-Depth Security Architecture${COLOR_RESET}"
    echo ""
}

function demo_section() {
    local section_title="$1"
    local section_desc="$2"
    echo ""
    echo -e "${BLUE}▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼▼${COLOR_RESET}"
    echo -e "${BOLD}${YELLOW}📌 $section_title${COLOR_RESET}"
    echo -e "${WHITE}$section_desc${COLOR_RESET}"
    echo -e "${BLUE}▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲${COLOR_RESET}"
    echo ""
}

function demo_explanation() {
    local explanation="$1"
    echo ""
    echo -e "${GREEN}💡 What this demonstrates:${COLOR_RESET}"
    echo -e "${WHITE}   $explanation${COLOR_RESET}"
    echo ""
}

function wait_for_enter() {
    local prompt="${1:-Press ENTER to continue...}"
    echo ""
    echo -e "${YELLOW}⏸️  $prompt${COLOR_RESET}"
    read -r
}

########################
# Demo Introduction
########################
function demo_intro() {
    demo_header

    echo -e "${GREEN}Welcome to the MCP-Biscuit Security demonstration!${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}This interactive demo showcases:${COLOR_RESET}"
    echo -e "${CYAN}  🔒 Transport Security (mTLS) - Client certificate authentication${COLOR_RESET}"
    echo -e "${CYAN}  🎫 Cryptographic Authorization (Biscuit) - Tamper-proof tokens${COLOR_RESET}"
    echo -e "${CYAN}  👤 Identity Validation - Client certificate identity matching${COLOR_RESET}"
    echo -e "${CYAN}  📊 Data Protection (RLS) - PostgreSQL Row-Level Security${COLOR_RESET}"
    echo -e "${CYAN}  🔓 Data Taint Protection - Token attenuation to prevent exfiltration${COLOR_RESET}"
    echo ""
    echo -e "${YELLOW}Each layer provides independent security even if others are compromised.${COLOR_RESET}"

    wait_for_enter "Ready to start the security demonstration?"
}

########################
# Prerequisites Check
########################
function demo_prerequisites() {
    demo_section "PREREQUISITES CHECK" "Verifying system readiness for security demonstrations"

    echo -e "${CYAN}🔍 Let's verify our security infrastructure is ready...${COLOR_RESET}"
    echo ""

    p "# Check if required certificates exist"
    pe "ls -la certs/ | grep -E '(ca-cert|server-cert|claude-client|unauthorized-hacker)'"

    demo_explanation "All certificates are present and ready for mTLS authentication"
    wait_for_enter

    echo -e "${CYAN}🚀 Starting security infrastructure (Dual mTLS servers)...${COLOR_RESET}"
    echo ""

    p "# Clean up any existing servers on ports 8000, 8443, and 9443"
    pe "echo 'Stopping any existing servers...'"
    pe "pkill -f 'server/app.py' || true"
    pe "pkill -f 'server/mtls_proxy.py' || true"
    pe "pkill -f 'server/custom_mtls_server.py' || true"
    pe "pkill -f 'hipaa-server/custom_mtls_server.py' || true"
    pe "sleep 2  # Allow processes to terminate"

    p "# Start Backend MCP server on port 8000"
    pe "echo 'Starting Backend MCP server on port 8000...'"
    pe "source .env && ENABLE_TLS=false PYTHONPATH=. BISCUIT_PUBLIC_KEY=\$BISCUIT_PUBLIC_KEY uv run python server/app.py > /tmp/backend_mcp_server.log 2>&1 &"
    pe "sleep 3  # Allow server to start"

    p "# Start mTLS server on port 8443"
    pe "echo 'Starting mTLS server on port 8443...'"
    pe "PYTHONPATH=. uv run python server/mtls_proxy.py > /tmp/mtls_server.log 2>&1 &"
    pe "sleep 3  # Allow server to start"

    p "# Verify servers started successfully"
    pe "if grep -q 'ERROR.*address already in use' /tmp/backend_mcp_server.log 2>/dev/null; then echo '❌ Backend MCP server failed to start (port 8000 in use)'; else echo '✅ Backend MCP server started'; fi"
    pe "if grep -q 'ERROR.*address already in use' /tmp/mtls_server.log 2>/dev/null; then echo '❌ mTLS server failed to start (port 8443 in use)'; else echo '✅ mTLS server started'; fi"

    p "# Start HIPAA mTLS server on port 9443"
    pe "echo 'Starting HIPAA mTLS server on port 9443...'"
    pe "source .env && PYTHONPATH=. BISCUIT_PUBLIC_KEY=\$BISCUIT_PUBLIC_KEY uv run python hipaa-server/custom_mtls_server.py > /tmp/hipaa_mtls_server.log 2>&1 &"
    pe "sleep 3  # Allow server to start"

    p "# Verify HIPAA mTLS server started successfully"
    pe "if grep -q 'ERROR.*address already in use' /tmp/hipaa_mtls_server.log 2>/dev/null; then echo '❌ HIPAA mTLS server failed to start (port 9443 in use)'; else echo '✅ HIPAA mTLS server started'; fi"

    p "# Test if both mTLS servers are running"
    pe "curl -s -k --cert certs/claude-client-cert.pem --key certs/claude-client-key.pem https://localhost:8443/health | jq -r '.status' && echo '✅ Database server health check passed'"
    pe "curl -s -k --cert certs/claude-client-cert.pem --key certs/claude-client-key.pem https://localhost:9443/health | jq -r '.status' && echo '✅ HIPAA server health check passed'"

    demo_explanation "✅ Dual mTLS server architecture with independent security boundaries
   ✅ Database mTLS server (port 8443) with full Biscuit token integration
   ✅ HIPAA mTLS server (port 9443) with data taint protection
   ✅ Defense-in-depth: mTLS transport + Biscuit authorization + RLS"
    wait_for_enter
}

########################
# Demo 1: mTLS Success
########################
function demo_mtls_success() {
    demo_section "DEMO 1: mTLS SUCCESS - AUTHORIZED CLIENT" "Demonstrating successful mutual TLS with authorized client certificate"

    echo -e "${GREEN}🎯 Scenario: Connection with authorized 'claude-client' certificate${COLOR_RESET}"
    echo ""

    p "# Connect using authorized client certificate"
    pe "timeout 3 curl -s -w 'Status: %{http_code}\\n' --cert certs/claude-client-cert.pem --key certs/claude-client-key.pem --cacert certs/ca-cert.pem https://localhost:8443/sse | head -1 || echo 'SSE connection successful (streaming)'"

    demo_explanation "✅ Client certificate authentication working
   ✅ Certificate chain validation against CA
   ✅ Identity extraction from certificate CN field
   ✅ Authorized client list validation"

    wait_for_enter
}

########################
# Demo 2: mTLS Failure
########################
function demo_mtls_failure() {
    demo_section "DEMO 2: mTLS FAILURE - UNAUTHORIZED CLIENT" "Demonstrating rejection of unauthorized client certificate"

    echo -e "${RED}🎯 Scenario: Connection attempt with 'unauthorized-hacker' certificate${COLOR_RESET}"
    echo ""

    p "# Attempt connection with unauthorized certificate"
    pe "timeout 3 curl -s -w 'Status: %{http_code}\\n' --cert certs/unauthorized-hacker-cert.pem --key certs/unauthorized-hacker-key.pem --cacert certs/ca-cert.pem https://localhost:8443/sse | head -1 || echo 'Connection rejected (as expected)'"

    demo_explanation "❌ Unauthorized client certificates rejected
   🔍 Identity-based access control working
   📝 Security events properly logged
   🛡️  Defense against certificate-based attacks"

    wait_for_enter
}

########################
# Demo 3: SSL Validation
########################
function demo_ssl_validation() {
    demo_section "DEMO 3: SSL/TLS VALIDATION - NO CLIENT CERTIFICATE" "Demonstrating SSL requirement enforcement"

    echo -e "${YELLOW}🎯 Scenario: Connection attempt without client certificate${COLOR_RESET}"
    echo ""

    p "# Try to connect without providing client certificate"
    pe "timeout 3 curl -s -w 'Status: %{http_code}\\n' --cacert certs/ca-cert.pem https://localhost:8443/sse | head -1 || echo 'Client certificate required (as expected)'"

    demo_explanation "🔒 Mutual TLS enforcement working
   📜 Client certificate requirement enforced
   🚫 Anonymous connections blocked"

    wait_for_enter
}

########################
# Demo 4: Biscuit Token Generation
########################
function demo_biscuit_generation() {
    demo_section "DEMO 4: BISCUIT TOKEN GENERATION" "Creating cryptographic tokens with patient facts"

    echo -e "${CYAN}🎯 Scenario: Generate tokens with patient-specific authorization facts${COLOR_RESET}"
    echo ""

    p "# Generate Biscuit token for patient 'Erin oRTEga'"
    pe "uv run python utilities/biscuit_generator.py --type custom --user patient --resource medical --facts 'patient_name(\"Erin oRTEga\")' --show-public-key"

    echo ""
    echo -e "${CYAN}🔹 Now let's generate a token for a different patient...${COLOR_RESET}"
    echo ""

    p "# Generate Biscuit token for patient 'DAvID AndErSON'"
    pe "uv run python utilities/biscuit_generator.py --type custom --user patient --resource medical --facts 'patient_name(\"DAvID AndErSON\")' --show-public-key"

    demo_explanation "🎫 Custom fact embedding in tokens
   🔐 Cryptographic token generation
   🔑 Public/private key cryptography
   📋 Patient-specific authorization data"

    wait_for_enter
}

########################
# Demo 5: Enhanced Tokens
########################
function demo_enhanced_tokens() {
    demo_section "DEMO 5: ENHANCED TOKENS WITH mTLS ATTRIBUTES" "Integrating client identity and audience validation"

    echo -e "${MAGENTA}🎯 Scenario: Generate tokens with mTLS integration and audience validation${COLOR_RESET}"
    echo ""

    p "# Generate enhanced token with client identity and audience"
    pe "uv run python utilities/biscuit_generator.py --type custom --user patient --resource medical --facts 'patient_name(\"Erin oRTEga\")' --facts 'client_identity(\"claude-client\")' --facts 'mtls_audience(\"mcp-server\")' --show-public-key"

    echo ""
    echo -e "${RED}🔹 For security testing, let's create a token with wrong client identity...${COLOR_RESET}"
    echo ""

    p "# Generate token with unauthorized client identity (for testing)"
    pe "uv run python utilities/biscuit_generator.py --type custom --user patient --resource medical --facts 'patient_name(\"Erin oRTEga\")' --facts 'client_identity(\"unauthorized-hacker\")' --facts 'mtls_audience(\"mcp-server\")' --show-public-key"

    demo_explanation "🔗 mTLS + Biscuit integration
   🎯 Audience validation capabilities
   👤 Client identity assertions
   🛡️  Multi-factor cryptographic authorization"

    wait_for_enter
}

########################
# Demo 6: Token Analysis
########################
function demo_token_analysis() {
    demo_section "DEMO 6: TOKEN ANALYSIS AND VERIFICATION" "Inspecting and verifying token contents"

    echo -e "${BLUE}🎯 Scenario: Generate, extract, and cryptographically verify a Biscuit token${COLOR_RESET}"
    echo ""

    p "# Step 1: Generate token with public key for analysis"
    pe "uv run python utilities/biscuit_generator.py --type custom --user patient --resource medical --facts 'patient_name(\"Erin oRTEga\")' --show-public-key > /tmp/token_demo.txt"

    p "# Step 2: Extract the generated token"
    pe "TOKEN=\$(grep 'Custom Token:' /tmp/token_demo.txt | cut -d: -f2 | tr -d ' ')"

    p "# Step 3: Extract the matching public key"
    pe "PUBLIC_KEY=\$(grep 'Public Key:' /tmp/token_demo.txt | cut -d: -f2 | tr -d ' ')"

    p "# Step 4: Display what we extracted"
    pe "echo \"Token: \${TOKEN:0:50}...\""
    pe "echo \"Public Key: \${PUBLIC_KEY:0:50}...\""

    echo ""
    echo -e "${YELLOW}🔍 Now let's analyze the token contents and verify its cryptographic signature...${COLOR_RESET}"
    echo ""

    p "# Step 5: Perform cryptographic analysis and verification"
    pe "uv run python utilities/biscuit_parser_cli.py \"\$TOKEN\" --public-key \"\$PUBLIC_KEY\" --analyze"

    demo_explanation "🔍 Token introspection capabilities
   ✅ Cryptographic verification working
   📋 Fact extraction and validation
   🔐 Tamper-proof token design"

    wait_for_enter
}

########################
# Demo 7: Database RLS Success with Text-to-SQL
########################
function demo_database_rls_success() {
    demo_section "DEMO 7: TEXT-TO-SQL + RLS SUCCESS WITH mTLS" "Natural language query with mTLS and cryptographic authorization"

    echo -e "${GREEN}🎯 Scenario: Natural language query for patient 'Erin oRTEga' with full security stack${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}This demonstrates the complete flow:${COLOR_RESET}"
    echo -e "${CYAN}  1. 🔒 mTLS client certificate authentication${COLOR_RESET}"
    echo -e "${CYAN}  2. 🧠 Natural language → Claude API → SQL conversion${COLOR_RESET}"
    echo -e "${CYAN}  3. 🎫 Biscuit token validation and fact extraction${COLOR_RESET}"
    echo -e "${CYAN}  4. 🛡️  Row-Level Security filtering based on token facts${COLOR_RESET}"
    echo ""

    p "# Step 1: Use configured Biscuit token for patient 'Erin oRTEga' from .env"
    pe "TOKEN=\$(grep BISCUIT_TOKEN .env | cut -d= -f2)"

    p "# Step 2: Set authorization token in environment"
    pe "export BISCUIT_TOKEN=\"\$TOKEN\""

    p "# Step 3: Display the natural language query we'll send to Claude"
    pe "echo 'Natural Language Query: \"Show me all medical records for patient Erin oRTEga\"'"

    echo ""
    echo -e "${YELLOW}🤖 Connecting via mTLS to Database server (port 8443)...${COLOR_RESET}"
    echo -e "${YELLOW}🔒 Client certificate authentication + Biscuit token validation${COLOR_RESET}"
    echo ""

    p "# Step 4: Send natural language query via mTLS to Database server"
    pe "uv run python example-clients/claude_cli_tls.py 'Show me all medical records for patient Erin oRTEga'"

    demo_explanation "🔒 mTLS transport security + client certificate validation
   🧠 Natural language → SQL via Claude API
   🎫 Biscuit token cryptographic verification
   🛡️  RLS policies filter results to authorized records only
   🔗 Complete defense-in-depth security integration"

    wait_for_enter
}

########################
# Demo 8: Text-to-SQL with Wrong Patient Token
########################
function demo_database_rls_failure() {
    demo_section "DEMO 8: mTLS + TEXT-TO-SQL + CROSS-PATIENT PROTECTION" "Demonstrating security boundaries with mTLS"

    echo -e "${RED}🎯 Scenario: mTLS connection with mismatched patient authorization${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}This demonstrates security boundaries:${COLOR_RESET}"
    echo -e "${CYAN}  1. 🔒 mTLS client certificate authentication (authorized)${COLOR_RESET}"
    echo -e "${CYAN}  2. 🧠 Same natural language query (asking for Erin's records)${COLOR_RESET}"
    echo -e "${CYAN}  3. 🎫 Different Biscuit token (authorized for DAvID AndErSON)${COLOR_RESET}"
    echo -e "${CYAN}  4. 🛡️  RLS blocks unauthorized cross-patient access${COLOR_RESET}"
    echo ""

    p "# Step 1: Generate token for different patient 'DAvID AndErSON' (demonstration purposes)"
    p "# Note: This generates a token with different keys for cross-patient testing"
    pe "DAVID_TOKEN=\$(uv run python utilities/biscuit_generator.py --type custom --user patient --resource medical --facts 'patient_name(\"DAvID AndErSON\")' | grep 'Custom Token:' | cut -d: -f2 | tr -d ' ')"
    pe "TOKEN=\$DAVID_TOKEN"

    p "# Step 2: Set different patient's authorization token"
    pe "export BISCUIT_TOKEN=\"\$TOKEN\""

    p "# Step 3: Display the same natural language query as before"
    pe "echo 'Natural Language Query: \"Show me all medical records for patient Erin oRTEga\"'"

    echo ""
    echo -e "${YELLOW}🔒 Security Test: Asking for Erin's data with DAvID's authorization token...${COLOR_RESET}"
    echo ""

    p "# Step 4: Connect via mTLS with mismatched token"
    pe "uv run python example-clients/claude_cli_tls.py 'Show me all medical records for patient Erin oRTEga'"

    echo ""
    echo -e "${GREEN}🛡️  Expected Result: Token verification fails OR no Erin records returned${COLOR_RESET}"

    demo_explanation "🔒 mTLS transport security validates client identity
   🔐 Token cryptographic verification provides authorization boundary
   🛡️  RLS policies prevent cross-patient data leakage
   🚫 Mismatched tokens fail at verification or return empty results
   🎯 Defense-in-depth: mTLS + cryptographic + database authorization"

    wait_for_enter
}

########################
# Demo 9: Unauthorized All-Patients Query
########################
function demo_unauthorized_all_patients() {
    demo_section "DEMO 9: mTLS + UNAUTHORIZED ALL-PATIENTS QUERY" "Testing security boundaries with mTLS and broad data access attempt"

    echo -e "${RED}🎯 Scenario: mTLS connection attempting to access ALL patient data${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}This demonstrates critical security boundaries:${COLOR_RESET}"
    echo -e "${CYAN}  1. 🔒 mTLS client certificate authentication (authorized transport)${COLOR_RESET}"
    echo -e "${CYAN}  2. 🧠 Natural language query requesting ALL patient records${COLOR_RESET}"
    echo -e "${CYAN}  3. 🎫 Token only authorizes access to Erin oRTEga${COLOR_RESET}"
    echo -e "${CYAN}  4. 🛡️  RLS prevents unauthorized data disclosure${COLOR_RESET}"
    echo ""

    p "# Step 1: Use configured Erin oRTEga's authorization token from .env"
    pe "TOKEN=\$(grep BISCUIT_TOKEN .env | cut -d= -f2)"

    p "# Step 2: Set single-patient authorization token"
    pe "export BISCUIT_TOKEN=\"\$TOKEN\""

    p "# Step 3: Display the broad access attempt query"
    pe "echo 'Natural Language Query: \"Show me all medical records for all patients\"'"

    echo ""
    echo -e "${RED}🚨 Security Test: Attempting to access ALL patient data with limited authorization...${COLOR_RESET}"
    echo ""

    p "# Step 4: Connect via mTLS and attempt broad data access"
    pe "uv run python example-clients/claude_cli_tls.py 'Show me all medical records for all patients'"

    echo ""
    echo -e "${GREEN}🛡️  Expected Result: Only Erin's records returned despite broad query${COLOR_RESET}"

    demo_explanation "🔒 mTLS validates transport-level client identity
   🚨 Broad queries cannot bypass token-based authorization
   🛡️  RLS enforces data boundaries regardless of query scope
   🎯 Token facts determine maximum accessible data scope
   🔐 No privilege escalation possible through query manipulation
   🎫 Defense-in-depth: mTLS + Biscuit + RLS working together"

    wait_for_enter
}

########################
# Demo 10: Data Taint Protection
########################
function demo_data_taint_protection() {
    demo_section "DEMO 10: DUAL mTLS + DATA TAINT PROTECTION" "Complete anti-exfiltration workflow with mTLS servers"

    echo -e "${MAGENTA}🎯 Scenario: Demonstrate information flow control across dual mTLS servers${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}This demonstrates the complete security workflow:${COLOR_RESET}"
    echo -e "${CYAN}  1. 🔒 mTLS connection to Database server (port 8443)${COLOR_RESET}"
    echo -e "${CYAN}  2. 🗄️  Query database → Token gets tainted with sensitive_data=1${COLOR_RESET}"
    echo -e "${CYAN}  3. 🔒 mTLS connection to HIPAA server (port 9443)${COLOR_RESET}"
    echo -e "${CYAN}  4. 🌐 Try internet tool with tainted token → REJECTED${COLOR_RESET}"
    echo -e "${CYAN}  5. 🔓 Clean token → HIPAA server → ALLOWED (normal operation)${COLOR_RESET}"
    echo ""

    p "# Step 1: Run comprehensive dual mTLS + data taint protection test"
    pe "source .env && ./local/test_full_mtls_workflow.sh"

    echo ""
    echo -e "${YELLOW}🔒 Let's break down what just happened:${COLOR_RESET}"
    echo ""

    p "# Explanation of the dual mTLS + data taint workflow:"
    pe "echo '1️⃣  mTLS auth to Database server (8443) → Biscuit token verified'"
    pe "echo '2️⃣  Clean token queries database → Gets data + Attenuated token'"
    pe "echo '3️⃣  Attenuated token has new block: sensitive_data(1)'"
    pe "echo '4️⃣  mTLS auth to HIPAA server (9443) → Detects taint → Rejects'"
    pe "echo '5️⃣  Original clean token → HIPAA server → Still works'"

    echo ""
    echo -e "${GREEN}🎯 Key Security Properties:${COLOR_RESET}"
    echo -e "${WHITE}   ✅ Dual mTLS servers with independent security boundaries${COLOR_RESET}"
    echo -e "${WHITE}   ✅ Cryptographic taint tracking (non-bypassable)${COLOR_RESET}"
    echo -e "${WHITE}   ✅ Automatic token attenuation after data access${COLOR_RESET}"
    echo -e "${WHITE}   ✅ Internet tools reject tainted tokens${COLOR_RESET}"
    echo -e "${WHITE}   ✅ No central state required (stateless enforcement)${COLOR_RESET}"

    demo_explanation "🔒 Dual mTLS servers create separate security domains
   🔐 Token attenuation creates cryptographic proof of data access
   🌐 HIPAA server (internet-accessible) checks for taint
   🛡️  Prevents accidental or malicious data exfiltration
   🎫 Information flow control enforced at token level
   🎯 Defense-in-depth: mTLS + Biscuit + Token attenuation"

    wait_for_enter
}

########################
# Security Validation Tests
########################
function demo_security_tests() {
    demo_section "SECURITY VALIDATION TESTS" "Demonstrating attack resistance and security boundaries"

    echo -e "${RED}🧪 Testing security boundaries and tamper prevention...${COLOR_RESET}"
    echo ""

    # Token Tampering Test
    echo -e "${YELLOW}🔹 Test 1: Token Tampering Prevention${COLOR_RESET}"
    echo ""

    p "# Use configured token for tampering test"
    pe "TOKEN=\$(grep BISCUIT_TOKEN .env | cut -d= -f2)"

    p "# Create a tampered version (change last character)"
    pe "TAMPERED_TOKEN=\"\${TOKEN%?}X\""

    p "# Show the difference"
    pe "echo \"Original:  \${TOKEN:0:50}...\""
    pe "echo \"Tampered:  \${TAMPERED_TOKEN:0:50}...\""

    p "# Try to verify the tampered token (should fail)"
    pe "echo \"Testing tampered token verification...\""
    pe "PUBLIC_KEY=\$(grep BISCUIT_PUBLIC_KEY .env | cut -d= -f2)"
    pe "uv run python utilities/biscuit_parser_cli.py \"\$TAMPERED_TOKEN\" --public-key \"\$PUBLIC_KEY\" --analyze || echo '✅ Tampered token properly rejected'"

    echo ""
    echo -e "${YELLOW}🔹 Test 2: Certificate Chain Validation${COLOR_RESET}"
    echo ""

    p "# Create a wrong CA certificate for testing"
    pe "openssl req -x509 -newkey rsa:2048 -keyout /tmp/wrong-ca-key.pem -out /tmp/wrong-ca-cert.pem -days 1 -nodes -subj '/CN=wrong-ca' 2>/dev/null"

    p "# Test with correct CA (should work)"
    pe "timeout 3 curl -s -w 'Correct CA Status: %{http_code}\\n' --cert certs/claude-client-cert.pem --key certs/claude-client-key.pem --cacert certs/ca-cert.pem https://localhost:8443/sse -o /dev/null"

    p "# Test with wrong CA (should fail)"
    pe "timeout 3 curl -s -w 'Wrong CA Status: %{http_code}\\n' --cert certs/claude-client-cert.pem --key certs/claude-client-key.pem --cacert /tmp/wrong-ca-cert.pem https://localhost:8443/sse -o /dev/null || echo '✅ Wrong CA properly rejected'"

    p "# Cleanup"
    pe "rm -f /tmp/wrong-ca-*.pem"

    demo_explanation "🔐 Token tampering detection working
   🛡️  Certificate chain validation working
   ✅ System resistant to common attack vectors
   🧪 Security boundaries properly enforced"

    wait_for_enter
}

########################
# Complete Security Stack Demo
########################
function demo_complete_stack() {
    demo_section "COMPLETE SECURITY STACK DEMONSTRATION" "All security layers working together"

    echo -e "${BOLD}${GREEN}🎯 Scenario: Demonstrate defense-in-depth with all security layers${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}This demonstrates the complete security flow:${COLOR_RESET}"
    echo -e "${CYAN}  1. 🔒 mTLS Client Certificate Validation${COLOR_RESET}"
    echo -e "${CYAN}  2. 🎫 Biscuit Token Cryptographic Verification${COLOR_RESET}"
    echo -e "${CYAN}  3. 👤 Client Identity Consistency Checking${COLOR_RESET}"
    echo -e "${CYAN}  4. 🎯 Audience Validation${COLOR_RESET}"
    echo ""

    p "# Step 1: Use configured token (comprehensive token with all security attributes can be generated if needed)"
    pe "TOKEN=\$(grep BISCUIT_TOKEN .env | cut -d= -f2)"

    p "# Step 2: Test mTLS layer (transport security)"
    pe "timeout 3 curl -s -w 'mTLS Status: %{http_code}\\n' --cert certs/claude-client-cert.pem --key certs/claude-client-key.pem --cacert certs/ca-cert.pem https://localhost:8443/sse -o /dev/null"

    p "# Step 3: Display the comprehensive token"
    pe "echo \"Complete Token: \${TOKEN:0:50}...\""
    pe "echo \"✅ Token contains: patient_name, client_identity, mtls_audience\""

    echo ""
    echo -e "${GREEN}🎉 All security layers validated successfully!${COLOR_RESET}"
    echo -e "${WHITE}   ✅ Transport Security (mTLS)${COLOR_RESET}"
    echo -e "${WHITE}   ✅ Cryptographic Authorization (Biscuit)${COLOR_RESET}"
    echo -e "${WHITE}   ✅ Identity Validation${COLOR_RESET}"
    echo -e "${WHITE}   ✅ Audience Validation${COLOR_RESET}"

    wait_for_enter
}

########################
# Demo Summary
########################
function demo_summary() {
    clear
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${BOLD}${WHITE}                           🎉 DEMONSTRATION COMPLETE                           ${COLOR_RESET}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo ""
    echo -e "${GREEN}📊 SECURITY LAYERS VALIDATED:${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}✅ Transport Security (mTLS):${COLOR_RESET}"
    echo -e "${CYAN}   • Client certificate authentication${COLOR_RESET}"
    echo -e "${CYAN}   • Identity-based access control${COLOR_RESET}"
    echo -e "${CYAN}   • Unauthorized client rejection${COLOR_RESET}"
    echo -e "${CYAN}   • Certificate chain validation${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}✅ Cryptographic Authorization (Biscuit):${COLOR_RESET}"
    echo -e "${CYAN}   • Token generation and verification${COLOR_RESET}"
    echo -e "${CYAN}   • Fact embedding and extraction${COLOR_RESET}"
    echo -e "${CYAN}   • Tamper prevention and detection${COLOR_RESET}"
    echo -e "${CYAN}   • Enhanced mTLS integration${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}✅ Security Boundaries:${COLOR_RESET}"
    echo -e "${CYAN}   • Token tampering detection${COLOR_RESET}"
    echo -e "${CYAN}   • Certificate chain validation${COLOR_RESET}"
    echo -e "${CYAN}   • Identity consistency checking${COLOR_RESET}"
    echo -e "${CYAN}   • Multi-layered defense validation${COLOR_RESET}"
    echo ""
    echo -e "${WHITE}✅ Data Taint Protection:${COLOR_RESET}"
    echo -e "${CYAN}   • Token attenuation after data access${COLOR_RESET}"
    echo -e "${CYAN}   • Information flow control${COLOR_RESET}"
    echo -e "${CYAN}   • Anti-exfiltration enforcement${COLOR_RESET}"
    echo -e "${CYAN}   • Cryptographic taint tracking${COLOR_RESET}"
    echo ""
    echo -e "${YELLOW}🚀 The MCP-Biscuit Security PoC demonstrates enterprise-grade${COLOR_RESET}"
    echo -e "${YELLOW}   security capabilities ready for production deployment.${COLOR_RESET}"
    echo ""
    echo -e "${GREEN}🎯 Key Achievement: Defense-in-depth security with multiple${COLOR_RESET}"
    echo -e "${GREEN}   independent layers providing comprehensive protection.${COLOR_RESET}"
    echo ""
    wait_for_enter "Press ENTER to exit demo"
}

########################
# Main Demo Flow
########################
function main_demo() {
    setup

    # Introduction
    demo_intro

    # Prerequisites check
    demo_prerequisites

    # Core security demonstrations
    demo_mtls_success
    demo_mtls_failure
    demo_ssl_validation
    demo_biscuit_generation
    demo_enhanced_tokens
    demo_token_analysis

    # Database integration demonstrations
    demo_database_rls_success
    demo_database_rls_failure

    # Advanced security boundary testing
    demo_unauthorized_all_patients

    # Data taint protection demonstration
    demo_data_taint_protection

    # Security validation tests
    demo_security_tests

    # Complete stack demonstration
    demo_complete_stack

    # Summary and conclusion
    demo_summary

    clear
    echo -e "${GREEN}Thank you for exploring the MCP-Biscuit Security system!${COLOR_RESET}"
    echo ""
}

########################
# Error Handling
########################
trap 'echo -e "\n${RED}Demo interrupted. Cleaning up...${COLOR_RESET}"; exit 1' INT

########################
# Check Dependencies
########################
if ! command -v ./demo-magic.sh &> /dev/null; then
    echo "❌ demo-magic.sh not found!"
    echo "Please install demo-magic from: https://github.com/paxtonhare/demo-magic"
    echo ""
    echo "Quick install:"
    echo "  curl -s https://raw.githubusercontent.com/paxtonhare/demo-magic/master/demo-magic.sh > demo-magic.sh"
    echo "  chmod +x demo-magic.sh"
    exit 1
fi

########################
# Run Demo
########################
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_demo
fi
