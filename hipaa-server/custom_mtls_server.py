#!/usr/bin/env python3
"""
Custom mTLS Server for HIPAA MCP Server

Provides mutual TLS authentication with client certificate validation for the HIPAA regulations server.
Similar to the database server's custom mTLS implementation, but for port 9443.
"""

import asyncio
import ssl
import json
import logging
import os
import sys
import traceback
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timezone

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from server.tls_config import TLSConfig

# Add hipaa-server to path
sys.path.insert(0, str(Path(__file__).parent))

from config import mcp

# Import and register MCP components
from tools.regulations import register_regulations_tools

logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


class HIPAAMTLSServer:
    """Custom mTLS HTTP server for HIPAA MCP server with client certificate authentication."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9443, cert_dir: str = "certs"):
        self.host = host
        self.port = port
        self.cert_dir = Path(cert_dir)
        self.tls_config = TLSConfig(cert_dir)
        self.server = None

        # Server's own identity (from its certificate)
        self.server_identity = "hipaa-mcp-server"

        # MCP session management
        self.mcp_sessions = {}  # session_id -> {read_stream_writer, client_identity}
        self.message_endpoint = "/messages/"

        # Register MCP components
        self.setup_mcp_server()

    def setup_mcp_server(self):
        """Register MCP resources, tools, and prompts."""
        try:
            logger.info("🔧 Registering HIPAA MCP tools")
            register_regulations_tools()
            logger.info("✅ HIPAA MCP server components registered")
        except Exception as e:
            logger.error(f"❌ Failed to setup HIPAA MCP server: {e}")

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with proper client certificate verification."""
        return self.tls_config.create_ssl_context()

    async def start(self):
        """Start the mTLS server."""
        ssl_context = self.create_ssl_context()

        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port,
            ssl=ssl_context
        )

        addr = self.server.sockets[0].getsockname()
        logger.info(f"🔒 HIPAA mTLS server started on https://{addr[0]}:{addr[1]}")
        logger.info(f"📋 Authorized clients: {self.tls_config.authorized_clients}")

        async with self.server:
            await self.server.serve_forever()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections with mTLS authentication."""
        client_addr = writer.get_extra_info('peername')
        logger.info(f"🔌 New connection from {client_addr}")

        try:
            # Get SSL socket to access client certificate
            ssl_object = writer.get_extra_info('ssl_object')

            if not ssl_object:
                logger.error(f"❌ No SSL object available for {client_addr}")
                await self.send_error_response(writer, 401, "Unauthorized",
                                             {"error": "No SSL connection"})
                return

            # Extract client identity from certificate
            client_identity = self.tls_config.extract_client_identity(ssl_object)

            if not client_identity:
                logger.warning(f"❌ Could not extract client identity from {client_addr}")
                await self.send_error_response(writer, 401, "Unauthorized",
                                             {"error": "No client certificate presented"})
                return

            # Check if client is authorized
            if not self.tls_config.is_client_authorized(client_identity):
                logger.warning(f"🚫 Unauthorized client '{client_identity}' from {client_addr}")
                await self.send_error_response(writer, 403, "Forbidden",
                                             {"error": f"Client '{client_identity}' is not authorized",
                                              "client_identity": client_identity})
                return

            logger.info(f"✅ Authorized client '{client_identity}' connected from {client_addr}")

            # Read HTTP request
            request_data = await reader.read(8192)
            request_text = request_data.decode('utf-8')

            # Parse HTTP request line and headers
            lines = request_text.split('\r\n')
            if not lines:
                await self.send_error_response(writer, 400, "Bad Request",
                                             {"error": "Empty request"})
                return

            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                await self.send_error_response(writer, 400, "Bad Request",
                                             {"error": "Invalid request line"})
                return

            method, path, http_version = parts[0], parts[1], parts[2]

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            logger.info(f"📝 {method} {path} from authorized client '{client_identity}'")

            # Route the request with token validation if present
            await self.route_request(reader, writer, method, path, headers, client_identity, request_data)

        except Exception as e:
            logger.error(f"❌ Error handling client {client_addr}: {e}")
            logger.error(traceback.format_exc())
            try:
                await self.send_error_response(writer, 500, "Internal Server Error",
                                             {"error": "Internal server error"})
            except:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def route_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, method: str, path: str,
                          headers: Dict[str, str], client_identity: str, request_data: bytes):
        """Route HTTP requests to appropriate handlers."""

        # Health check endpoint
        if path == "/health" or path == "/":
            response_data = {
                "status": "healthy",
                "server": "HIPAA MCP Server with mTLS",
                "client_identity": client_identity,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await self.send_json_response(writer, 200, "OK", response_data)

        elif path == "/sse":
            # SSE endpoint for MCP protocol with FastMCP integration
            logger.info(f"🔌 SSE connection request from {client_identity}")
            await self.handle_sse_request_fastmcp(reader, writer, method, path, headers, client_identity, request_data)

        elif path.startswith("/messages/"):
            # MCP message endpoint for bidirectional communication via FastMCP
            logger.info(f"📨 FastMCP message request from {client_identity}: {path}")
            await self.handle_message_request_fastmcp(reader, writer, method, path, headers, client_identity, request_data)

        else:
            # Unknown endpoint
            await self.send_error_response(writer, 404, "Not Found",
                                         {"error": "Endpoint not found", "path": path})

    async def handle_sse_request_fastmcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, method: str, path: str, headers: Dict[str, str], client_identity: str, request_data: bytes):
        """Handle SSE requests using FastMCP SSE transport with mTLS authentication."""
        try:
            logger.info(f"✅ Processing FastMCP SSE request for authenticated client: {client_identity}")

            # Create ASGI scope similar to what Hypercorn provides
            scope = {
                "type": "http",
                "http_version": "1.1",
                "method": method,
                "scheme": "https",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "root_path": "",
                "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
                "server": ("localhost", self.port),
                "client": ("127.0.0.1", 0),
                "asgi": {"version": "3.0", "spec_version": "2.1"},
                "mcp_client_identity": client_identity,
            }

            # Create message queue for ASGI communication
            receive_queue = asyncio.Queue()
            send_queue = asyncio.Queue()

            # Add HTTP request start message
            await receive_queue.put({
                "type": "http.request",
                "body": b"",
                "more_body": False,
            })

            async def asgi_receive():
                return await receive_queue.get()

            async def asgi_send(message):
                await send_queue.put(message)

            # Create FastMCP SSE app instance
            sse_app = mcp.sse_app()

            # Start ASGI app in background
            async def run_asgi_app():
                try:
                    await sse_app(scope, asgi_receive, asgi_send)
                except Exception as e:
                    logger.error(f"❌ ASGI app error: {e}")
                    logger.error(traceback.format_exc())

            # Start the app task
            asgi_task = asyncio.create_task(run_asgi_app())

            # Process ASGI messages and convert to HTTP response
            response_started = False

            while True:
                try:
                    # Wait for messages from ASGI app with timeout
                    message = await asyncio.wait_for(send_queue.get(), timeout=30.0)

                    if message["type"] == "http.response.start":
                        # Send HTTP response headers
                        status = message["status"]
                        headers_list = message.get("headers", [])

                        response_headers = f"HTTP/1.1 {status} OK\r\n"
                        for header_name, header_value in headers_list:
                            response_headers += f"{header_name.decode()}: {header_value.decode()}\r\n"
                        response_headers += "\r\n"

                        writer.write(response_headers.encode())
                        await writer.drain()
                        response_started = True
                        logger.info(f"📤 FastMCP SSE headers sent to {client_identity}")

                    elif message["type"] == "http.response.body":
                        # Send response body (SSE events)
                        body = message.get("body", b"")
                        if body:
                            writer.write(body)
                            await writer.drain()
                            logger.debug(f"📤 FastMCP SSE event sent to {client_identity}: {body[:100]}...")

                        # Check if this is the last chunk
                        if not message.get("more_body", True):
                            logger.info(f"🔌 FastMCP SSE connection completed for {client_identity}")
                            break

                except asyncio.TimeoutError:
                    logger.warning(f"⏰ FastMCP SSE timeout for {client_identity}")
                    break
                except Exception as e:
                    logger.error(f"❌ Error processing FastMCP SSE message for {client_identity}: {e}")
                    break

            # Clean up
            if not asgi_task.done():
                asgi_task.cancel()

        except Exception as e:
            logger.error(f"❌ FastMCP SSE handling failed for {client_identity}: {e}")
            logger.error(traceback.format_exc())
            try:
                if not response_started:
                    error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nSSE connection failed"
                    writer.write(error_response.encode())
                    await writer.drain()
            except:
                pass

    async def handle_message_request_fastmcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, method: str, path: str, headers: Dict[str, str], client_identity: str, request_data: bytes):
        """Handle MCP message requests using FastMCP transport with mTLS authentication."""
        try:
            logger.info(f"✅ Processing FastMCP message request for authenticated client: {client_identity}")

            # Read the full request body if POST
            body = b""
            if method == "POST":
                # Extract JSON from request body
                if '\r\n\r\n' in request_data.decode('utf-8'):
                    json_part = request_data.decode('utf-8').split('\r\n\r\n', 1)[1]
                elif '\n\n' in request_data.decode('utf-8'):
                    json_part = request_data.decode('utf-8').split('\n\n', 1)[1]
                else:
                    json_part = ""

                if json_part.strip():
                    body = json_part.encode()
                else:
                    # Try to read more data
                    additional_data = await reader.read(8192)
                    if additional_data:
                        combined_data = request_data + additional_data
                        request_text = combined_data.decode('utf-8')
                        if '\r\n\r\n' in request_text:
                            json_part = request_text.split('\r\n\r\n', 1)[1]
                            body = json_part.encode()

            # Create ASGI scope for the message request
            scope = {
                "type": "http",
                "http_version": "1.1",
                "method": method,
                "scheme": "https",
                "path": path,
                "raw_path": path.encode(),
                "query_string": path.split('?', 1)[1].encode() if '?' in path else b"",
                "root_path": "",
                "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
                "server": ("localhost", self.port),
                "client": ("127.0.0.1", 0),
                "asgi": {"version": "3.0", "spec_version": "2.1"},
                "mcp_client_identity": client_identity,
            }

            # Create message queues for ASGI communication
            receive_queue = asyncio.Queue()
            send_queue = asyncio.Queue()

            # Add HTTP request messages
            await receive_queue.put({
                "type": "http.request",
                "body": body,
                "more_body": False,
            })

            async def asgi_receive():
                return await receive_queue.get()

            async def asgi_send(message):
                await send_queue.put(message)

            # Create FastMCP SSE app instance
            sse_app = mcp.sse_app()

            # Start ASGI app in background
            async def run_asgi_app():
                try:
                    await sse_app(scope, asgi_receive, asgi_send)
                except Exception as e:
                    logger.error(f"❌ ASGI app error: {e}")
                    logger.error(traceback.format_exc())

            # Start the app task
            asgi_task = asyncio.create_task(run_asgi_app())

            # Process ASGI messages and convert to HTTP response
            response_started = False
            response_body = b""

            while True:
                try:
                    # Wait for messages from ASGI app with timeout
                    message = await asyncio.wait_for(send_queue.get(), timeout=10.0)

                    if message["type"] == "http.response.start":
                        # Send HTTP response headers
                        status = message["status"]
                        headers_list = message.get("headers", [])

                        response_headers = f"HTTP/1.1 {status} OK\r\n"
                        for header_name, header_value in headers_list:
                            response_headers += f"{header_name.decode()}: {header_value.decode()}\r\n"
                        response_headers += "\r\n"

                        writer.write(response_headers.encode())
                        await writer.drain()
                        response_started = True
                        logger.debug(f"📤 FastMCP message response headers sent to {client_identity}")

                    elif message["type"] == "http.response.body":
                        # Accumulate response body
                        body_chunk = message.get("body", b"")
                        if body_chunk:
                            response_body += body_chunk

                        # Check if this is the last chunk
                        if not message.get("more_body", True):
                            writer.write(response_body)
                            await writer.drain()
                            logger.debug(f"📤 FastMCP message response sent to {client_identity}: {response_body[:100]}...")
                            break

                except asyncio.TimeoutError:
                    logger.warning(f"⏰ FastMCP message timeout for {client_identity}")
                    break
                except Exception as e:
                    logger.error(f"❌ Error processing FastMCP message for {client_identity}: {e}")
                    break

            # Clean up
            if not asgi_task.done():
                asgi_task.cancel()

        except Exception as e:
            logger.error(f"❌ FastMCP message handling failed for {client_identity}: {e}")
            logger.error(traceback.format_exc())
            try:
                if not response_started:
                    error_response = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"error\": \"Message processing failed\"}"
                    writer.write(error_response.encode())
                    await writer.drain()
            except:
                pass

    async def send_json_response(self, writer: asyncio.StreamWriter, status_code: int,
                                status_text: str, data: Dict[str, Any]):
        """Send JSON HTTP response."""
        json_data = json.dumps(data, indent=2)
        response = (
            f"HTTP/1.1 {status_code} {status_text}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(json_data)}\r\n"
            f"\r\n"
            f"{json_data}"
        )
        writer.write(response.encode())
        await writer.drain()

    async def send_error_response(self, writer: asyncio.StreamWriter, status_code: int,
                                 status_text: str, error_data: Dict[str, str]):
        """Send error response."""
        await self.send_json_response(writer, status_code, status_text, error_data)


async def main():
    """Main entry point for HIPAA mTLS server."""
    server = HIPAAMTLSServer(host="0.0.0.0", port=9443, cert_dir="certs")
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
