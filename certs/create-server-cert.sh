#!/bin/bash
# Create Server Certificate for MCP mTLS

set -e

echo "Creating MCP Server Certificate..."

# Generate server private key
openssl genrsa -out server-key.pem 4096

# Create certificate signing request
openssl req -subj "/C=US/ST=Demo/L=Demo/O=MCP-Biscuit-Server/CN=mcp-server" -new -key server-key.pem -out server.csr

# Create extensions file for server certificate
cat > server-extensions.cnf << EOF
subjectAltName = DNS:mcp-server,DNS:localhost,IP:127.0.0.1,IP:0.0.0.0
extendedKeyUsage = serverAuth
keyUsage = digitalSignature,keyEncipherment
EOF

# Sign the server certificate with CA
openssl x509 -req -days 365 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -out server-cert.pem -extfile server-extensions.cnf -CAcreateserial

# Clean up
rm server.csr server-extensions.cnf

# Set appropriate permissions
chmod 400 server-key.pem
chmod 444 server-cert.pem

echo "Server certificate created:"
echo "  Private Key: server-key.pem"
echo "  Certificate: server-cert.pem"