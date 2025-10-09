#!/usr/bin/env python3
"""
HIPAA Regulations MCP Server Configuration

Provides configuration and initialization for the HIPAA regulations monitoring server.
"""

import logging
import os
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("hipaa-regulations-server", dependencies=["httpx>=0.28.1"], port=8001)

# Server configuration
ECFR_API_URL = "https://www.ecfr.gov/api/versioner/v1/structure/2025-09-29/title-45.json"
CACHE_DIR = Path(__file__).parent / "cache"
CACHE_FILE = CACHE_DIR / "title-45.json"

# Ensure cache directory exists
CACHE_DIR.mkdir(exist_ok=True)

logger.info("HIPAA Regulations MCP server configured")
