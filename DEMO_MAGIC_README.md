# 🎭 Demo Magic Security Presentation

Interactive terminal presentation for the MCP-Biscuit Security system using demo-magic for live demonstrations.

## 🚀 Quick Start

### 1. Install demo-magic and dependencies

```bash
# Download demo-magic script
curl -s https://raw.githubusercontent.com/paxtonhare/demo-magic/master/demo-magic.sh > demo-magic.sh
chmod +x demo-magic.sh

# Install pv (pipe viewer) for typing effects
# Ubuntu/Debian:
sudo apt-get install pv
# macOS:
brew install pv
# CentOS/RHEL:
sudo yum install pv
```

**Note**: If `pv` is not available, the script will still work but without the live typing effects.

### 2. Start mTLS Server

```bash
# In a separate terminal, start the server
PYTHONPATH=. uv run python server/custom_mtls_server.py
```

### 3. Run the Demo

```bash
# Run the interactive security presentation
./demo_magic_security.sh
```

## 🎬 Presentation Features

### ✨ **Interactive Demo Flow**
- **Live Typing Effects** - Commands appear as if being typed in real-time
- **Presenter Control** - Press ENTER to execute each command
- **Visual Headers** - Clear section breaks with colored formatting
- **Explanatory Blocks** - Educational content between demonstrations

### 🛡️ **Security Demonstrations Covered**

1. **📋 Prerequisites Check** - System readiness validation
2. **🔒 mTLS Success** - Authorized client certificate authentication
3. **❌ mTLS Failure** - Unauthorized client rejection
4. **🚫 SSL Validation** - Client certificate requirement enforcement
5. **🎫 Biscuit Generation** - Cryptographic token creation
6. **🔗 Enhanced Tokens** - mTLS + Biscuit integration
7. **🔍 Token Analysis** - Verification and inspection
8. **🧠 Text-to-SQL + RLS Success** - Natural language query with authorization
9. **🔒 Text-to-SQL + Cross-Patient Protection** - RLS filtering demonstration
10. **🚨 Unauthorized All-Patients Query** - Broad access attempt blocked by RLS
11. **🧪 Security Tests** - Tampering and attack resistance
12. **🎯 Complete Stack** - All layers working together

### 🎨 **Visual Elements**
- Color-coded output (success/failure/info)
- Unicode emojis for visual appeal
- Structured section headers
- Progress indicators
- Clear explanations of security concepts

## 🎯 **Demo Controls**

During the presentation:
- **ENTER** - Execute the current command
- **Ctrl+C** - Exit the demo gracefully
- Commands are pre-validated and safe to run

## 🔧 **Customization**

### Typing Speed
Modify the `TYPE_SPEED` variable:
```bash
TYPE_SPEED=20  # Adjust 1-100 (higher = faster)
```

### Demo Prompt
Customize the shell prompt:
```bash
DEMO_PROMPT="${GREEN}🛡️  MCP-Biscuit Security ${CYAN}\W ${COLOR_RESET}"
```

### Adding New Sections
Follow this pattern:
```bash
function demo_new_section() {
    demo_section "SECTION TITLE" "Section description"

    echo -e "${CYAN}🎯 Scenario: What you're demonstrating${COLOR_RESET}"
    echo ""

    p "# Comment explaining the command"
    pe "actual-command-to-execute"

    demo_explanation "What this proves about security"
    wait_for_enter
}
```

## 📊 **Use Cases**

### 🎓 **Training Sessions**
- Security team education
- New developer onboarding
- Architecture reviews

### 👥 **Customer Demonstrations**
- Sales presentations
- Technical evaluations
- Proof-of-concept validation

### 🔍 **Security Audits**
- Penetration testing validation
- Compliance demonstrations
- Vulnerability assessments

### 🧪 **Development Testing**
- Feature validation
- Integration testing
- Regression testing

## 🛠️ **Requirements**

### System Requirements
- Bash shell (Linux/macOS)
- curl command available
- OpenSSL tools installed
- Python 3.13+ with uv

### Project Requirements
- MCP-Biscuit PoC repository
- All certificates generated (`certs/` directory)
- mTLS server running on port 8443
- Environment configuration (`.env` file)

### Dependencies
- **demo-magic** - Interactive terminal presentation framework
- **uv** - Python package manager
- **All project dependencies** - As per main project requirements

## 🎨 **Color Scheme**

The presentation uses consistent colors:
- 🔵 **Blue** - Headers and structure
- 🟢 **Green** - Success messages and positive outcomes
- 🔴 **Red** - Failures and security rejections
- 🟡 **Yellow** - Warnings and important information
- 🟣 **Magenta** - Special features and highlights
- 🟦 **Cyan** - Commands and technical details
- ⚪ **White** - Explanatory text

## 🚨 **Troubleshooting**

### Demo-magic Not Found
```bash
❌ demo-magic.sh not found!
```
**Solution**: Download demo-magic as shown in installation steps.

### PV (Pipe Viewer) Not Available
```bash
⚠️  pv not available - disabling typing effects
```
**Solution**: Install pv for typing effects:
```bash
# Ubuntu/Debian:
sudo apt-get install pv
# macOS:
brew install pv
```
**Alternative**: The demo will work without typing effects if pv is not available.

### Server Not Running
```bash
❌ mTLS server not responding
```
**Solution**: Start the server in a separate terminal:
```bash
PYTHONPATH=. uv run python server/custom_mtls_server.py
```

### Certificate Issues
```bash
❌ SSL certificate verification failed
```
**Solution**: Generate certificates:
```bash
cd certs
./create-ca.sh
./create-server-cert.sh
./create-client-cert.sh claude-client
./create-client-cert.sh unauthorized-hacker
```

### Permission Denied
```bash
❌ Permission denied: ./demo_magic_security.sh
```
**Solution**: Make script executable:
```bash
chmod +x demo_magic_security.sh
```

## 📝 **Script Structure**

```
demo_magic_security.sh
├── Configuration (colors, speed, prompt)
├── Utility Functions (headers, sections, explanations)
├── Demo Functions (one per security demonstration)
├── Main Flow (orchestrates the complete presentation)
├── Error Handling (graceful cleanup and exit)
└── Dependency Checking (validates demo-magic availability)
```

## 🎉 **Demo Outcomes**

After running the complete presentation, attendees will have seen:

### ✅ **Security Validations**
- All 4 security layers working correctly
- Attack resistance demonstrated
- Defense-in-depth validated

### 🎓 **Educational Value**
- Understanding of mTLS authentication
- Cryptographic token concepts
- Multi-layered security architecture

### 🚀 **Production Readiness**
- Enterprise-grade security capabilities
- Real-world usage scenarios
- Complete system integration

---

**Ready to deliver an impressive security demonstration!** 🎯