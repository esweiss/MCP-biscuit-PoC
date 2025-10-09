#!/usr/bin/env python3
"""
Custom asyncio HTTP server with proper mTLS client certificate support.
This server can access client certificates and enforce identity-based access control.
"""

import asyncio
import ssl
import json
import logging
import sys
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import traceback
import os
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from server.tls_config import TLSConfig
from server.config import mcp

# Import MCP SSE transport
from mcp.server.sse import SseServerTransport
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.shared.session import SessionMessage
from mcp.types import JSONRPCMessage
import anyio
from uuid import uuid4
import uuid

# Import and register MCP components
from server.resources.schema import register_schema_resources
from server.resources.data import register_data_resources
from server.resources.extensions import register_extension_resources
from server.tools.connection import register_connection_tools
from server.tools.query import register_query_tools
from server.tools.viz import register_viz_tools
from server.prompts.natural_language import register_natural_language_prompts
from server.prompts.data_visualization import register_data_visualization_prompts

logger = logging.getLogger(__name__)

class MTLSHTTPServer:
    """Custom HTTP server with proper mTLS client certificate handling."""
    
    def __init__(self, host="0.0.0.0", port=8443, cert_dir="certs"):
        self.host = host
        self.port = port
        self.cert_dir = Path(cert_dir)
        self.tls_config = TLSConfig(cert_dir)
        self.server = None

        # Initialize Biscuit parser for token validation
        self.biscuit_parser = None
        self.setup_biscuit_validation()

        # Server's own identity (from its certificate)
        self.server_identity = "mcp-server"  # This should match the server certificate CN

        # MCP session management
        self.mcp_sessions = {}  # session_id -> {read_stream_writer, client_identity}
        self.message_endpoint = "/messages/"

        # Register MCP components
        self.setup_mcp_server()
        
    def setup_biscuit_validation(self):
        """Initialize Biscuit token validation with public key from environment."""
        try:
            import sys
            sys.path.append('.')
            from biscuit_parser_module import BiscuitParser
            
            # Get Biscuit public key from environment
            public_key = os.getenv('BISCUIT_PUBLIC_KEY')
            if public_key:
                self.biscuit_parser = BiscuitParser(public_key)
                logger.info("🔐 Biscuit token validation enabled")
            else:
                logger.warning("⚠️  BISCUIT_PUBLIC_KEY not found - Biscuit validation disabled")
                
        except Exception as e:
            logger.error(f"❌ Failed to initialize Biscuit validation: {e}")

    def setup_mcp_server(self):
        """Register MCP resources, tools, and prompts."""
        try:
            logger.info("🔧 Registering MCP resources and tools")
            register_schema_resources()
            register_extension_resources()
            register_data_resources()
            register_connection_tools()
            register_query_tools()
            register_viz_tools()
            register_natural_language_prompts()
            register_data_visualization_prompts()
            logger.info("✅ MCP server components registered")
        except Exception as e:
            logger.error(f"❌ Failed to setup MCP server: {e}")

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with proper client certificate verification."""
        return self.tls_config.create_ssl_context()
    
    def validate_biscuit_token(self, token: str, client_identity: str) -> Dict[str, Any]:
        """Validate Biscuit token with mTLS attestation."""
        if not self.biscuit_parser:
            return {
                "valid": False,
                "error": "Biscuit validation not initialized"
            }
        
        try:
            # Validate mTLS attestation in the token
            validation_result = self.biscuit_parser.validate_mtls_attestation(
                token, 
                client_identity, 
                self.server_identity
            )
            
            if not validation_result.get("mtls_validation", False):
                return {
                    "valid": False,
                    "error": "mTLS attestation validation failed",
                    "details": validation_result.get("validation_details", {})
                }
            
            # Extract user information from primary block
            facts_result = self.biscuit_parser.verify_and_extract_facts(token)
            if facts_result.get("status") != "verified_with_facts":
                return {
                    "valid": False,
                    "error": "Token verification failed",
                    "details": facts_result
                }
            
            # Extract user from facts
            users = facts_result.get("facts", {}).get("users", [])
            primary_user = None
            if users and len(users) > 0:
                user_fact = users[0]
                if isinstance(user_fact, dict) and "u" in user_fact:
                    primary_user = user_fact["u"]
            
            return {
                "valid": True,
                "client_identity": client_identity,
                "server_identity": self.server_identity,
                "primary_user": primary_user,
                "validation_details": validation_result.get("validation_details", {}),
                "token_facts": facts_result.get("facts", {})
            }
            
        except Exception as e:
            logger.error(f"❌ Biscuit token validation error: {e}")
            return {
                "valid": False,
                "error": f"Validation exception: {str(e)}"
            }
    
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
            
            # Route the request with token validation if present
            await self.route_request(reader, writer, method, path, headers, client_identity, request_data)
            
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
    
    async def route_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, method: str, path: str,
                          headers: Dict[str, str], client_identity: str, request_data: bytes):
        """Route HTTP requests to appropriate handlers."""
        
        # Check for Biscuit token in Authorization header
        biscuit_token = None
        biscuit_validation = None
        
        auth_header = headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            biscuit_token = auth_header[7:]  # Remove "Bearer " prefix
            logger.info(f"🎫 Biscuit token provided, validating...")
            
            # Validate the Biscuit token
            biscuit_validation = self.validate_biscuit_token(biscuit_token, client_identity)
            
            if not biscuit_validation.get("valid", False):
                logger.warning(f"❌ Biscuit token validation failed: {biscuit_validation.get('error')}")
                await self.send_error_response(writer, 403, "Forbidden", {
                    "error": "Biscuit token validation failed",
                    "details": biscuit_validation.get("error"),
                    "validation_details": biscuit_validation.get("details", {})
                })
                return
            else:
                logger.info(f"✅ Biscuit token valid for user: {biscuit_validation.get('primary_user')}")
        
        if path == "/":
            # Root endpoint - return success for authorized clients
            response_data = {
                "message": "mTLS authentication successful",
                "client_identity": client_identity,
                "server": "Custom mTLS HTTP Server",
                "status": "authorized"
            }
            
            # Include Biscuit validation results if token was provided
            if biscuit_validation:
                response_data["biscuit_validation"] = {
                    "valid": biscuit_validation.get("valid"),
                    "primary_user": biscuit_validation.get("primary_user"),
                    "client_identity_verified": biscuit_validation.get("client_identity") == client_identity,
                    "server_identity_verified": biscuit_validation.get("server_identity") == self.server_identity
                }
                response_data["message"] = "mTLS + Biscuit dual authentication successful"
            
            await self.send_json_response(writer, 200, "OK", response_data)
            
        elif path == "/health":
            # Health check endpoint
            response_data = {
                "status": "healthy",
                "client_identity": client_identity,
                "mtls": "enabled"
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

    async def handle_sse_request(self, writer: asyncio.StreamWriter, headers: Dict[str, str], client_identity: str):
        """Handle SSE request implementing proper MCP SSE protocol."""
        try:
            logger.info(f"✅ Processing SSE request for authenticated client: {client_identity}")

            # Send SSE headers
            sse_headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: keep-alive\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Headers: *\r\n"
                "\r\n"
            )

            writer.write(sse_headers.encode())
            await writer.drain()

            logger.info(f"✅ SSE headers sent to {client_identity}")

            # Create session ID and setup MCP streams
            session_id = uuid4()

            # Create memory streams for MCP communication
            read_stream_writer, read_stream = anyio.create_memory_object_stream(0)
            write_stream, write_stream_reader = anyio.create_memory_object_stream(0)

            # Store session for message endpoint access
            self.mcp_sessions[session_id] = {
                "read_stream_writer": read_stream_writer,
                "write_stream_reader": write_stream_reader,
                "client_identity": client_identity
            }

            logger.info(f"📋 Created MCP session {session_id} for {client_identity}")

            # Send endpoint event to client (this is what the client expects)
            endpoint_event = f"event: endpoint\r\ndata: {self.message_endpoint}?session_id={session_id}\r\n\r\n"
            writer.write(endpoint_event.encode())
            await writer.drain()

            logger.info(f"📤 Sent endpoint event to {client_identity}: {self.message_endpoint}?session_id={session_id}")

            # Start MCP server session in background
            async def run_mcp_session():
                try:
                    logger.info(f"🚀 Starting MCP server session for {client_identity}")
                    await mcp._mcp_server.run(
                        read_stream,
                        write_stream,
                        mcp._mcp_server.create_initialization_options()
                    )
                except Exception as e:
                    logger.error(f"❌ MCP session error for {client_identity}: {e}")
                finally:
                    # Clean up session
                    if session_id in self.mcp_sessions:
                        del self.mcp_sessions[session_id]
                    logger.info(f"🧹 Cleaned up MCP session {session_id}")

            # Start the MCP session task
            import asyncio
            asyncio.create_task(run_mcp_session())

            # Keep the SSE connection alive and handle write stream
            try:
                async for session_message in write_stream_reader:
                    # Extract the JSON-RPC message from the SessionMessage
                    jsonrpc_message = session_message.message

                    # Send MCP messages as SSE events with correct format
                    sse_message = f"event: message\r\ndata: {jsonrpc_message.model_dump_json(by_alias=True, exclude_none=True)}\r\n\r\n"

                    writer.write(sse_message.encode())
                    await writer.drain()

                    logger.debug(f"📤 Sent SSE message to {client_identity}: {jsonrpc_message.model_dump_json(by_alias=True, exclude_none=True)}")
            except Exception as e:
                logger.info(f"🔌 SSE connection ended for {client_identity}: {e}")

        except Exception as e:
            logger.error(f"❌ SSE handling failed for {client_identity}: {e}")
            logger.error(traceback.format_exc())
            try:
                error_response = f"data: {{\"error\": \"SSE connection failed\", \"details\": \"{str(e)}\"}}\r\n\r\n"
                writer.write(error_response.encode())
                await writer.drain()
            except:
                pass

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
                "server": ("localhost", 8443),
                "client": ("127.0.0.1", 0),  # Client info from mTLS
                "asgi": {"version": "3.0", "spec_version": "2.1"},
                "mcp_client_identity": client_identity,  # Custom field for our mTLS identity
            }

            # Create message queue for ASGI communication
            import asyncio
            receive_queue = asyncio.Queue()
            send_queue = asyncio.Queue()

            # Add HTTP request start message
            await receive_queue.put({
                "type": "http.request",
                "body": b"",  # No body for SSE GET request
                "more_body": False,
            })

            async def asgi_receive():
                return await receive_queue.get()

            async def asgi_send(message):
                await send_queue.put(message)

            # Create FastMCP SSE app instance
            from server.config import mcp
            sse_app = mcp.sse_app()

            # Start ASGI app in background
            async def run_asgi_app():
                try:
                    await sse_app(scope, asgi_receive, asgi_send)
                except Exception as e:
                    logger.error(f"❌ ASGI app error: {e}")
                    logger.error(traceback.format_exc())

            # Start the app task
            import asyncio
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
                "server": ("localhost", 8443),
                "client": ("127.0.0.1", 0),
                "asgi": {"version": "3.0", "spec_version": "2.1"},
                "mcp_client_identity": client_identity,
            }

            # Create message queues for ASGI communication
            import asyncio
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
            from server.config import mcp
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

    async def handle_message_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, method: str, path: str, headers: Dict[str, str], client_identity: str, request_data: bytes):
        """Handle MCP message requests (bidirectional communication)."""
        try:
            # Extract session ID from path
            if "session_id=" not in path:
                await self.send_error_response(writer, 400, "Bad Request",
                                             {"error": "Missing session_id parameter"})
                return

            session_id_str = path.split("session_id=")[1].split("&")[0]
            try:
                session_id = uuid.UUID(session_id_str)
            except ValueError:
                await self.send_error_response(writer, 400, "Bad Request",
                                             {"error": "Invalid session_id format"})
                return

            # Check if session exists
            if session_id not in self.mcp_sessions:
                await self.send_error_response(writer, 404, "Not Found",
                                             {"error": "Session not found"})
                return

            session = self.mcp_sessions[session_id]

            # Verify client identity matches session
            if session["client_identity"] != client_identity:
                await self.send_error_response(writer, 403, "Forbidden",
                                             {"error": "Client identity mismatch"})
                return

            if method == "POST":
                # Handle incoming MCP message from client
                try:
                    # For now, read additional data to get the request body
                    # In a proper implementation, we'd parse Content-Length from headers
                    # and read exactly that many bytes
                    additional_data = await reader.read(8192)

                    # Extract JSON from request body (simple approach)
                    # Look for JSON data after the double newline
                    combined_data = request_data + additional_data if additional_data else request_data
                    request_text = combined_data.decode('utf-8')

                    # Find the JSON payload (after headers)
                    if '\r\n\r\n' in request_text:
                        json_part = request_text.split('\r\n\r\n', 1)[1]
                    elif '\n\n' in request_text:
                        json_part = request_text.split('\n\n', 1)[1]
                    else:
                        json_part = ""

                    if json_part.strip():
                        # Parse the JSON-RPC message
                        message_data = json.loads(json_part)
                        jsonrpc_message = JSONRPCMessage.model_validate(message_data)

                        # Create SessionMessage and send to MCP server
                        session_message = SessionMessage(message=jsonrpc_message, metadata={})

                        # Send to the read stream for the MCP server to process
                        read_stream_writer = session["read_stream_writer"]
                        await read_stream_writer.send(session_message)

                        logger.info(f"📨 Processed MCP message from {client_identity}: {jsonrpc_message.method if hasattr(jsonrpc_message, 'method') else 'unknown'}")

                        # Return success
                        await self.send_json_response(writer, 200, "OK", {"status": "message processed"})
                    else:
                        await self.send_error_response(writer, 400, "Bad Request", {"error": "No JSON body found"})

                except json.JSONDecodeError as e:
                    logger.error(f"❌ JSON decode error for {client_identity}: {e}")
                    await self.send_error_response(writer, 400, "Bad Request", {"error": "Invalid JSON"})
                except Exception as e:
                    logger.error(f"❌ Error processing MCP message for {client_identity}: {e}")
                    await self.send_error_response(writer, 500, "Internal Server Error", {"error": "Message processing failed"})

            else:
                await self.send_error_response(writer, 405, "Method Not Allowed",
                                             {"error": f"Method {method} not allowed"})

        except Exception as e:
            logger.error(f"❌ Message handling failed for {client_identity}: {e}")
            logger.error(traceback.format_exc())
            await self.send_error_response(writer, 500, "Internal Server Error",
                                         {"error": "Message handling failed"})

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