#!/bin/bash
# Create Client Certificate for MCP mTLS

set -e

CLIENT_NAME=${1:-mcp-client}
echo "Creating MCP Client Certificate for: $CLIENT_NAME"

# Generate client private key
openssl genrsa -out ${CLIENT_NAME}-key.pem 4096

# Create certificate signing request
openssl req -subj "/C=US/ST=Demo/L=Demo/O=MCP-Biscuit-Client/CN=$CLIENT_NAME" -new -key ${CLIENT_NAME}-key.pem -out ${CLIENT_NAME}.csr

# Create extensions file for client certificate
cat > ${CLIENT_NAME}-extensions.cnf << EOF
extendedKeyUsage = clientAuth
keyUsage = digitalSignature
EOF

# Sign the client certificate with CA
openssl x509 -req -days 365 -in ${CLIENT_NAME}.csr -CA ca-cert.pem -CAkey ca-key.pem -out ${CLIENT_NAME}-cert.pem -extfile ${CLIENT_NAME}-extensions.cnf -CAcreateserial

# Clean up
rm ${CLIENT_NAME}.csr ${CLIENT_NAME}-extensions.cnf

# Set appropriate permissions
chmod 400 ${CLIENT_NAME}-key.pem
chmod 444 ${CLIENT_NAME}-cert.pem

echo "Client certificate created:"
echo "  Private Key: ${CLIENT_NAME}-key.pem"
echo "  Certificate: ${CLIENT_NAME}-cert.pem"