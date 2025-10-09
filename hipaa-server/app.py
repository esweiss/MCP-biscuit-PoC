#!/usr/bin/env python3
"""
HIPAA Regulations MCP Server

An MCP server for monitoring HIPAA regulations from eCFR with Biscuit token authentication.
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Add hipaa-server to path
hipaa_server_dir = Path(__file__).parent
if str(hipaa_server_dir) not in sys.path:
    sys.path.insert(0, str(hipaa_server_dir))

from config import mcp
from tools.regulations import register_regulations_tools

logger = logging.getLogger(__name__)

# Configure logging level from environment
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.getLogger().setLevel(getattr(logging, log_level))

logger.info("Initializing HIPAA Regulations MCP Server")

# Register tools
register_regulations_tools()

logger.info("✅ HIPAA Regulations MCP server initialized")


async def run_server():
    """Run the HIPAA regulations server."""
    # Check if TLS should be enabled
    enable_tls = os.environ.get("ENABLE_TLS", "false").lower() == "true"

    if enable_tls:
        logger.info("Starting HIPAA MCP server with HTTP transport (TLS handled by proxy)")
        await mcp.run_streamable_http_async()
    else:
        logger.info("Starting HIPAA MCP server with SSE transport (no TLS)")
        await mcp.run_sse_async()


if __name__ == "__main__":
    asyncio.run(run_server())
