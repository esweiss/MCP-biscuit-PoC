#!/usr/bin/env python3
"""
Custom asyncio HTTP server with proper mTLS client certificate support.
This server can access client certificates and enforce identity-based access control.
"""

import asyncio
import ssl
import json
import logging
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import traceback

from server.tls_config import TLSConfig

logger = logging.getLogger(__name__)

class MTLSHTTPServer:
    """Custom HTTP server with proper mTLS client certificate handling."""
    
    def __init__(self, host="0.0.0.0", port=8443, cert_dir="certs"):
        self.host = host
        self.port = port
        self.cert_dir = Path(cert_dir)
        self.tls_config = TLSConfig(cert_dir)
        self.server = None
        
    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with proper client certificate verification."""
        return self.tls_config.create_ssl_context()
    
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle individual client connections with mTLS verification."""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {client_addr}")
        
        try:
            # Get SSL transport information
            transport = writer.transport
            ssl_object = transport.get_extra_info('ssl_object')
            
            client_cert_der = None
            client_identity = None
            
            if ssl_object:
                try:
                    # Get peer certificate in DER format
                    client_cert_der = ssl_object.getpeercert(binary_form=True)
                    if client_cert_der:
                        # Verify the client certificate
                        if self.tls_config.verify_client_certificate(client_cert_der):
                            client_identity = self.tls_config.get_client_identity(client_cert_der)
                            logger.info(f"✅ Authorized client connected: {client_identity}")
                        else:
                            client_identity = self.tls_config.get_client_identity(client_cert_der)
                            logger.warning(f"❌ Unauthorized client attempted connection: {client_identity}")
                            
                            # Reject unauthorized client with 403 Forbidden
                            await self.send_error_response(writer, 403, "Forbidden", 
                                                         {"error": "Client certificate not authorized",
                                                          "client_identity": client_identity})
                            return
                    else:
                        logger.warning("❌ No client certificate provided")
                        await self.send_error_response(writer, 401, "Unauthorized",
                                                     {"error": "Client certificate required"})
                        return
                        
                except Exception as e:
                    logger.error(f"❌ Failed to verify client certificate: {e}")
                    await self.send_error_response(writer, 500, "Internal Server Error",
                                                 {"error": "Certificate verification failed"})
                    return
            else:
                logger.error("❌ No SSL object found in transport")
                await self.send_error_response(writer, 500, "Internal Server Error",
                                             {"error": "SSL information not available"})
                return
            
            # Read HTTP request
            request_data = await reader.read(8192)
            if not request_data:
                return
                
            request_text = request_data.decode('utf-8')
            request_lines = request_text.strip().split('\n')
            request_line = request_lines[0] if request_lines else ""
            
            # Parse request line
            parts = request_line.strip().split()
            if len(parts) < 3:
                await self.send_error_response(writer, 400, "Bad Request", 
                                             {"error": "Invalid HTTP request"})
                return
                
            method, path, version = parts[0], parts[1], parts[2]
            
            # Parse headers
            headers = {}
            for line in request_lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            logger.info(f"📝 {method} {path} from authorized client '{client_identity}'")
            
            # Route the request
            await self.route_request(writer, method, path, headers, client_identity)
            
        except Exception as e:
            logger.error(f"❌ Error handling client {client_addr}: {e}")
            logger.error(traceback.format_exc())
            try:
                await self.send_error_response(writer, 500, "Internal Server Error",
                                             {"error": "Server error"})
            except:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def route_request(self, writer: asyncio.StreamWriter, method: str, path: str, 
                          headers: Dict[str, str], client_identity: str):
        """Route HTTP requests to appropriate handlers."""
        
        if path == "/":
            # Root endpoint - return success for authorized clients
            response_data = {
                "message": "mTLS authentication successful",
                "client_identity": client_identity,
                "server": "Custom mTLS HTTP Server",
                "status": "authorized"
            }
            await self.send_json_response(writer, 200, "OK", response_data)
            
        elif path == "/health":
            # Health check endpoint
            response_data = {
                "status": "healthy",
                "client_identity": client_identity,
                "mtls": "enabled"
            }
            await self.send_json_response(writer, 200, "OK", response_data)
            
        elif path.startswith("/mcp"):
            # MCP endpoints - route to MCP server
            response_data = {
                "message": "MCP endpoint access authorized",
                "client_identity": client_identity,
                "path": path,
                "note": "MCP integration would be implemented here"
            }
            await self.send_json_response(writer, 200, "OK", response_data)
            
        else:
            # Unknown endpoint
            await self.send_error_response(writer, 404, "Not Found",
                                         {"error": "Endpoint not found", "path": path})
    
    async def send_json_response(self, writer: asyncio.StreamWriter, status_code: int, 
                               status_text: str, data: Dict[str, Any]):
        """Send JSON HTTP response."""
        json_data = json.dumps(data, indent=2)
        response = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(json_data)}\r\n"
            f"Connection: close\r\n"
            f"Server: Custom-mTLS-Server/1.0\r\n"
            f"\r\n"
            f"{json_data}"
        )
        
        writer.write(response.encode())
        await writer.drain()
    
    async def send_error_response(self, writer: asyncio.StreamWriter, status_code: int,
                                status_text: str, error_data: Dict[str, Any]):
        """Send error HTTP response."""
        await self.send_json_response(writer, status_code, status_text, error_data)
    
    async def start(self):
        """Start the mTLS HTTP server."""
        ssl_context = self.create_ssl_context()
        
        logger.info(f"🚀 Starting Custom mTLS HTTP Server")
        logger.info(f"📋 Authorized clients: {self.tls_config.authorized_clients}")
        
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            ssl=ssl_context
        )
        
        logger.info(f"✅ Custom mTLS HTTP Server running on https://{self.host}:{self.port}")
        logger.info(f"🔐 Client certificate verification: ENABLED")
        logger.info(f"🎯 Press Ctrl+C to stop")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        """Stop the server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("🛑 Custom mTLS HTTP Server stopped")

async def main():
    """Main server entry point."""
    import sys
    sys.path.append('..')
    
    # Configure logging
    from server.logging_config import configure_logging
    configure_logging(level="INFO")
    
    server = MTLSHTTPServer()
    
    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("🛑 Shutting down server...")
        await server.stop()
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    asyncio.run(main())