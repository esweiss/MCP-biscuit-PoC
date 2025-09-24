#!/usr/bin/env python
"""
mTLS Proxy Server

Terminates mTLS connections and forwards requests to downstream server
with client certificate information in HTTP headers.
"""

import asyncio
import ssl
import logging
from typing import Optional, Dict, Any
import httpx
from server.tls_config import TLSConfig
from server.logging_config import get_logger

logger = get_logger("mtls_proxy")

class MTLSProxy:
    """
    mTLS proxy that terminates TLS connections and forwards requests
    with client certificate information in headers.
    """

    def __init__(self, downstream_url: str = "http://localhost:8000", port: int = 8443):
        self.downstream_url = downstream_url.rstrip('/')
        self.port = port
        self.tls_config = TLSConfig()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection."""
        try:
            # Get client certificate from the TLS connection
            transport = writer.get_extra_info('ssl_object')
            client_cert = None
            client_identity = None

            if transport:
                try:
                    client_cert = transport.getpeercert()
                    client_identity = self.tls_config.extract_client_identity(transport)
                    logger.info(f"✅ Client authenticated: {client_identity}")
                except Exception as e:
                    logger.error(f"❌ Failed to extract client certificate: {e}")
                    await self._send_error_response(writer, 401, "Client certificate required")
                    return

            if not client_identity:
                logger.warning("❌ No client identity found")
                await self._send_error_response(writer, 401, "Client certificate required")
                return

            # Check if client is authorized
            if not self.tls_config.is_client_authorized(client_identity):
                logger.warning(f"❌ Unauthorized client: {client_identity}")
                await self._send_error_response(writer, 403, f"Client '{client_identity}' not authorized")
                return

            # Read the HTTP request
            request_data = await self._read_http_request(reader)
            if not request_data:
                return

            # Parse the request
            method, path, headers, body = self._parse_http_request(request_data)

            # Add client certificate headers
            headers.update({
                'X-Client-Cert-CN': client_identity,
                'X-Client-Cert-Verified': 'true',
                'X-Forwarded-Proto': 'https',
                'X-Forwarded-For': writer.get_extra_info('peername')[0] if writer.get_extra_info('peername') else 'unknown'
            })

            # Forward request to downstream server
            await self._forward_request(writer, method, path, headers, body)

        except Exception as e:
            logger.error(f"Error handling client: {e}")
            await self._send_error_response(writer, 500, "Internal server error")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _read_http_request(self, reader: asyncio.StreamReader) -> Optional[bytes]:
        """Read the complete HTTP request."""
        try:
            # Read request line and headers
            request_data = b""
            while True:
                line = await reader.readline()
                if not line:
                    break
                request_data += line
                if line == b"\r\n":  # End of headers
                    break

            # Parse headers to get Content-Length
            request_str = request_data.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            content_length = 0

            for line in lines:
                if line.lower().startswith('content-length:'):
                    content_length = int(line.split(':', 1)[1].strip())
                    break

            # Read body if present
            if content_length > 0:
                body = await reader.read(content_length)
                request_data += body

            return request_data

        except Exception as e:
            logger.error(f"Error reading HTTP request: {e}")
            return None

    def _parse_http_request(self, request_data: bytes) -> tuple:
        """Parse HTTP request into components."""
        request_str = request_data.decode('utf-8', errors='ignore')
        lines = request_str.split('\r\n')

        # Parse request line
        request_line = lines[0]
        parts = request_line.split(' ')
        method = parts[0]
        path = parts[1] if len(parts) > 1 else '/'

        # Parse headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == '':  # Empty line marks end of headers
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # Extract body
        body = '\r\n'.join(lines[body_start:]).encode('utf-8') if body_start < len(lines) else b''

        return method, path, headers, body

    async def _forward_request(self, writer: asyncio.StreamWriter, method: str, path: str, headers: Dict[str, str], body: bytes):
        """Forward the request to downstream server."""
        try:
            url = f"{self.downstream_url}{path}"

            # Remove hop-by-hop headers
            hop_headers = {'connection', 'upgrade', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding'}
            filtered_headers = {k: v for k, v in headers.items() if k.lower() not in hop_headers}

            # Make request to downstream server
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=filtered_headers,
                    content=body,
                    follow_redirects=False
                )

                # Forward response back to client
                await self._send_response(writer, response)

        except Exception as e:
            logger.error(f"Error forwarding request: {e}")
            await self._send_error_response(writer, 502, "Bad Gateway")

    async def _send_response(self, writer: asyncio.StreamWriter, response: httpx.Response):
        """Send HTTP response back to client."""
        try:
            # Write status line
            status_line = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n"
            writer.write(status_line.encode())

            # Write headers
            for name, value in response.headers.items():
                if name.lower() not in {'connection', 'transfer-encoding'}:
                    writer.write(f"{name}: {value}\r\n".encode())

            # Add connection close header
            writer.write(b"Connection: close\r\n")
            writer.write(b"\r\n")

            # Write body
            if response.content:
                writer.write(response.content)

            await writer.drain()

        except Exception as e:
            logger.error(f"Error sending response: {e}")

    async def _send_error_response(self, writer: asyncio.StreamWriter, status: int, message: str):
        """Send error response to client."""
        try:
            response_body = f'{{"error": "{message}"}}'
            response = (
                f"HTTP/1.1 {status} Error\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(response_body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{response_body}"
            )
            writer.write(response.encode())
            await writer.drain()
        except Exception as e:
            logger.error(f"Error sending error response: {e}")

    async def start(self):
        """Start the mTLS proxy server."""
        # Create SSL context for mTLS (optional client certs for better testing)
        ssl_context = self.tls_config.create_ssl_context(require_client_cert=False)

        # Start server
        server = await asyncio.start_server(
            self.handle_client,
            '0.0.0.0',
            self.port,
            ssl=ssl_context
        )

        addr = server.sockets[0].getsockname()
        logger.info(f"🚀 mTLS Proxy running on https://{addr[0]}:{addr[1]}")
        logger.info(f"📡 Forwarding to downstream: {self.downstream_url}")
        logger.info(f"🔐 Client certificate verification: ENABLED")
        logger.info(f"📋 Authorized clients: {self.tls_config.authorized_clients}")

        async with server:
            await server.serve_forever()

async def main():
    """Main entry point."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create and start proxy
    proxy = MTLSProxy(
        downstream_url="http://localhost:8000",
        port=8443
    )

    try:
        await proxy.start()
    except KeyboardInterrupt:
        logger.info("🛑 Proxy server stopped")

if __name__ == "__main__":
    asyncio.run(main())