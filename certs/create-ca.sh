#!/bin/bash
# Create Certificate Authority for MCP mTLS Demo

set -e

echo "Creating Certificate Authority..."

# Generate CA private key
openssl genrsa -out ca-key.pem 4096

# Create extensions file for CA certificate
cat > ca-extensions.cnf << EOF
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

# Create CA certificate
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca-cert.pem -subj "/C=US/ST=Demo/L=Demo/O=MCP-Biscuit-CA/CN=MCP-Biscuit-CA" -extensions v3_ca -config <(cat /etc/ssl/openssl.cnf <(echo -e "\n[v3_ca]\nbasicConstraints = critical,CA:true\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash"))

# Clean up
rm -f ca-extensions.cnf

echo "Certificate Authority created:"
echo "  Private Key: ca-key.pem"
echo "  Certificate: ca-cert.pem"

# Set appropriate permissions
chmod 400 ca-key.pem
chmod 444 ca-cert.pem

echo "CA setup complete!"