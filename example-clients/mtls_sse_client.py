# example-clients/mtls_sse_client.py
import asyncio
import ssl
import httpx
from typing import AsyncGenerator, Tuple
from mcp.client.sse import SSEClientTransport
from mcp.shared.context import RequestContext
from mcp.types import JSONRPCMessage
import anyio
import logging
from client_tls import ClientTLS

logger = logging.getLogger(__name__)

class MTLSSSEClientTransport:
    """SSE client transport with mTLS support."""
    
    def __init__(self, url: str, client_tls: ClientTLS):
        self.url = url
        self.client_tls = client_tls
        self.ssl_context = client_tls.create_ssl_context()
    
    async def __aenter__(self):
        # Create HTTPX client with our SSL context
        self.httpx_client = httpx.AsyncClient(verify=self.ssl_context)
        
        # Create SSE transport
        self.transport = SSEClientTransport(self.url)
        
        # Monkey patch the transport to use our HTTP client
        original_create_http_client = self.transport._create_http_client
        
        def patched_create_http_client():
            return self.httpx_client
        
        self.transport._create_http_client = patched_create_http_client
        
        return await self.transport.__aenter__()
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        result = await self.transport.__aexit__(exc_type, exc_val, exc_tb)
        await self.httpx_client.aclose()
        return result

async def mtls_sse_client(url: str, client_name: str = "claude-client") -> AsyncGenerator[Tuple[anyio.abc.ByteReceiveStream, anyio.abc.ByteSendStream], None]:
    """Create mTLS-enabled SSE client."""
    client_tls = ClientTLS(cert_dir="../certs", client_name=client_name)
    
    async with MTLSSSEClientTransport(url, client_tls) as transport:
        yield transport