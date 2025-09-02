#!/usr/bin/env python3
"""
Enhanced Security Demo Setup Script

This script helps set up the environment for running the enhanced mTLS + Biscuit
security demonstration and tests.

What it does:
1. Checks for required certificates
2. Generates Biscuit keys if needed
3. Validates environment setup
4. Provides instructions for running demos and tests
"""

import os
import sys
import subprocess
from pathlib import Path

def check_certificates():
    """Check if required certificates exist."""
    print("🔐 Checking certificates...")
    
    cert_files = [
        "certs/ca-cert.pem",
        "certs/server-cert.pem", 
        "certs/server-key.pem",
        "certs/claude-client-cert.pem",
        "certs/claude-client-key.pem"
    ]
    
    missing_files = []
    for cert_file in cert_files:
        if not Path(cert_file).exists():
            missing_files.append(cert_file)
    
    if missing_files:
        print("❌ Missing certificate files:")
        for file in missing_files:
            print(f"   • {file}")
        print("\n🔧 Generate certificates with:")
        print("   cd certs")
        print("   ./create-ca.sh")
        print("   ./create-server-cert.sh")
        print("   ./create-client-cert.sh claude-client")
        return False
    else:
        print("✅ All certificates found")
        return True

def setup_biscuit_keys():
    """Setup Biscuit keys in environment."""
    print("\n🎫 Setting up Biscuit keys...")
    
    # Check if keys already exist in environment
    existing_private = os.getenv('BISCUIT_PRIVATE_KEY')
    existing_public = os.getenv('BISCUIT_PUBLIC_KEY')
    
    if existing_private and existing_public:
        print("✅ Biscuit keys already configured in environment")
        print(f"   Public key: {existing_public[:32]}...")
        return True
    
    # Generate new keys
    try:
        sys.path.append('.')
        from utilities.biscuit_generator import BiscuitGenerator
        
        generator = BiscuitGenerator()
        private_key = generator.private_key.to_hex()
        public_key = generator.get_public_key()
        
        print("🔑 Generated new Biscuit keypair")
        print(f"   Private key: {private_key[:32]}...")
        print(f"   Public key: {public_key[:32]}...")
        
        # Create .env file or append to existing
        env_file = Path('.env')
        env_content = []
        
        if env_file.exists():
            env_content = env_file.read_text().splitlines()
        
        # Remove any existing key lines
        env_content = [line for line in env_content 
                      if not line.startswith('BISCUIT_PRIVATE_KEY=') 
                      and not line.startswith('BISCUIT_PUBLIC_KEY=')]
        
        # Add new keys
        env_content.append(f"BISCUIT_PRIVATE_KEY={private_key}")
        env_content.append(f"BISCUIT_PUBLIC_KEY={public_key}")
        
        env_file.write_text('\n'.join(env_content) + '\n')
        
        print("✅ Keys saved to .env file")
        print("⚠️  Restart your terminal or source .env to use these keys")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to generate Biscuit keys: {e}")
        return False

def check_python_environment():
    """Check Python environment and dependencies."""
    print("\n🐍 Checking Python environment...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print(f"❌ Python {sys.version_info.major}.{sys.version_info.minor} is too old (need 3.8+)")
        return False
    else:
        print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} is supported")
    
    # Check key dependencies
    required_packages = [
        'biscuit_auth',
        'requests',
        'cryptography'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing packages:")
        for pkg in missing_packages:
            print(f"   • {pkg}")
        print("\n🔧 Install with: uv add " + " ".join(missing_packages))
        return False
    else:
        print("✅ All required packages available")
        return True

def print_demo_instructions():
    """Print instructions for running demos and tests."""
    print("\n📋 ENHANCED SECURITY DEMO INSTRUCTIONS")
    print("="*60)
    
    print("\n1️⃣  START THE MTLS SERVER:")
    print("   PYTHONPATH=. uv run python server/custom_mtls_server.py")
    
    print("\n2️⃣  RUN INDIVIDUAL DEMOS (in separate terminal):")
    print("   # Basic enhanced security demo")
    print("   uv run python demo_enhanced_security.py --user alice")
    print("")
    print("   # Test wrong client identity (should fail)")
    print("   uv run python test_wrong_client_identity.py")
    print("")
    print("   # Test wrong server audience (should fail)")
    print("   uv run python test_wrong_audience.py")
    print("")
    print("   # Test wrong user identity")
    print("   uv run python test_wrong_user_identity.py")
    print("")
    print("   # Test data retrieval")
    print("   uv run python test_data_retrieval.py")
    
    print("\n3️⃣  RUN COMPREHENSIVE TEST SUITE:")
    print("   uv run python run_all_security_tests.py")
    
    print("\n4️⃣  RUN INDIVIDUAL COMPREHENSIVE TESTS:")
    print("   uv run python test_enhanced_mtls_biscuit.py")
    
    print("\n5️⃣  USE THE EXISTING CLIENT:")
    print("   # Get keys from .env file")
    print("   export BISCUIT_PRIVATE_KEY=$(grep BISCUIT_PRIVATE_KEY .env | cut -d= -f2)")
    print("   export BISCUIT_PUBLIC_KEY=$(grep BISCUIT_PUBLIC_KEY .env | cut -d= -f2)")
    print("")
    print("   # Create base token")
    print("   BASE_TOKEN=$(uv run python utilities/biscuit_generator.py \\")
    print("     --type custom \\")
    print("     --facts 'user(\"alice\")' 'patient_name(\"Erin oRTEga\")' \\")
    print("     --private-key $BISCUIT_PRIVATE_KEY)")
    print("")
    print("   # Use with mTLS client")
    print("   uv run python example-clients/mtls_biscuit_client.py \\")
    print("     --base-token \"$BASE_TOKEN\" \\")
    print("     --private-key $BISCUIT_PRIVATE_KEY \\")
    print("     --public-key $BISCUIT_PUBLIC_KEY")

def main():
    """Main setup execution."""
    print("🚀 ENHANCED SECURITY DEMO SETUP")
    print("="*60)
    print("This script will help you set up the enhanced mTLS + Biscuit security demo.")
    
    success = True
    
    # Check Python environment
    if not check_python_environment():
        success = False
    
    # Check certificates
    if not check_certificates():
        success = False
    
    # Setup Biscuit keys
    if not setup_biscuit_keys():
        success = False
    
    # Print summary
    print(f"\n📊 SETUP SUMMARY")
    print("="*60)
    if success:
        print("✅ Setup completed successfully!")
        print("🎉 You're ready to run the enhanced security demos.")
        print_demo_instructions()
    else:
        print("❌ Setup incomplete. Please address the issues above.")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())