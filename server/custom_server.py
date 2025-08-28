#!/usr/bin/env python3
"""
Custom server implementation that properly handles client certificates.
This is an alternative approach using a custom ASGI server.
"""

import asyncio
import ssl
import socket
from typing import Dict, Any, Optional
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ClientCertInfo:
    """Container for client certificate information."""
    def __init__(self, cert_der: bytes, identity: str):
        self.cert_der = cert_der
        self.identity = identity

class MTLSServer:
    """Custom ASGI server with proper mTLS support."""
    
    def __init__(self, app, host="0.0.0.0", port=8443, cert_dir="certs"):
        self.app = app
        self.host = host
        self.port = port
        self.cert_dir = Path(cert_dir)
        self.client_certs: Dict[str, ClientCertInfo] = {}
        
    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for mTLS."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load server certificate and key
        server_cert = self.cert_dir / "server-cert.pem"
        server_key = self.cert_dir / "server-key.pem"
        ca_cert = self.cert_dir / "ca-cert.pem"
        
        context.load_cert_chain(str(server_cert), str(server_key))
        context.load_verify_locations(str(ca_cert))
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        
        return context
    
    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle individual client connections."""
        try:
            # Get client certificate from the SSL transport
            transport = writer.transport
            ssl_object = transport.get_extra_info('ssl_object')
            
            client_cert_der = None
            client_identity = None
            
            if ssl_object:
                try:
                    # Get peer certificate
                    client_cert_der = ssl_object.getpeercert(binary_form=True)
                    if client_cert_der:
                        # Extract client identity
                        import cryptography.x509
                        from cryptography.x509.oid import NameOID
                        
                        cert = cryptography.x509.load_der_x509_certificate(client_cert_der)
                        client_identity = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                        
                        logger.info(f"Client connected: {client_identity}")
                        
                        # Store client certificate info
                        connection_id = f"{transport.get_extra_info('peername')[0]}:{transport.get_extra_info('peername')[1]}"
                        self.client_certs[connection_id] = ClientCertInfo(client_cert_der, client_identity)
                        
                except Exception as e:
                    logger.error(f"Failed to get client certificate: {e}")
            
            # Handle HTTP request (simplified)
            data = await reader.read(1024)
            if data:
                request_line = data.decode().split('\n')[0]
                logger.info(f"Request: {request_line}")
                
                # Check authorization
                authorized_clients = ["claude-client", "authorized-client"]
                
                if client_identity and client_identity in authorized_clients:
                    response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found"
                    logger.info(f"Authorized client '{client_identity}' - returning 404")
                else:
                    response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 49\r\n\r\n{\"error\": \"Client certificate not authorized\"}"
                    logger.warning(f"Unauthorized client '{client_identity}' - returning 403")
                
                writer.write(response.encode())
                await writer.drain()
            
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def start(self):
        """Start the mTLS server."""
        ssl_context = self.create_ssl_context()
        
        server = await asyncio.start_server(
            self.handle_connection,
            self.host,
            self.port,
            ssl=ssl_context
        )
        
        logger.info(f"mTLS server started on https://{self.host}:{self.port}")
        
        async with server:
            await server.serve_forever()

if __name__ == "__main__":
    import sys
    sys.path.append('..')
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a dummy ASGI app (we'll implement HTTP handling directly for now)
    async def dummy_app(scope, receive, send):
        pass
    
    server = MTLSServer(dummy_app)
    
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        logger.info("Server stopped")