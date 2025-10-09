#!/usr/bin/env python3
"""
HIPAA Regulations MCP Client

A simple client to interact with the HIPAA regulations MCP server.
Tests HIPAA regulation monitoring with Biscuit token authentication.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client

# Load environment variables
from dotenv import load_dotenv
load_dotenv()


async def main():
    """Main client function to interact with HIPAA MCP server."""

    # Get configuration from environment
    hipaa_mcp_url = os.getenv("HIPAA_MCP_URL", "http://localhost:8001/sse")
    biscuit_token = os.getenv("BISCUIT_TOKEN")

    if not biscuit_token:
        print("❌ Error: BISCUIT_TOKEN not found in environment")
        print("Please set BISCUIT_TOKEN in .env file")
        return 1

    print(f"Connecting to HIPAA MCP server at {hipaa_mcp_url}...")

    try:
        async with sse_client(url=hipaa_mcp_url) as streams:
            print("✅ SSE streams established, creating session...")

            async with ClientSession(*streams) as session:
                print("✅ Session created, initializing...")

                # Initialize the connection
                await session.initialize()
                print("✅ Connection initialized!")

                # List available tools
                tools_result = await session.list_tools()
                print(f"\n📋 Available tools: {len(tools_result.tools)}")
                for tool in tools_result.tools:
                    print(f"  - {tool.name}: {tool.description}")

                # Test 1: Check for HIPAA updates
                print("\n" + "="*80)
                print("TEST 1: Checking for HIPAA updates")
                print("="*80)

                result = await session.call_tool(
                    "check_hipaa_updates",
                    arguments={"biscuit_token": biscuit_token}
                )

                print("\n📊 Result:")
                if result.content:
                    for content_item in result.content:
                        if hasattr(content_item, 'text'):
                            response_data = json.loads(content_item.text)
                            print(json.dumps(response_data, indent=2))

                            if response_data.get("success"):
                                if response_data.get("has_updates"):
                                    print("\n✅ Changes detected in HIPAA regulations!")
                                else:
                                    print("\n✅ No changes detected - regulations are current")
                            else:
                                print(f"\n❌ Error: {response_data.get('error')}")

                # Test 2: Get HIPAA structure (Privacy Rule - Part 160)
                print("\n" + "="*80)
                print("TEST 2: Getting HIPAA Privacy Rule structure (Part 160)")
                print("="*80)

                result = await session.call_tool(
                    "get_hipaa_structure",
                    arguments={
                        "biscuit_token": biscuit_token,
                        "section": "160"
                    }
                )

                print("\n📊 Result:")
                if result.content:
                    for content_item in result.content:
                        if hasattr(content_item, 'text'):
                            response_data = json.loads(content_item.text)

                            if response_data.get("success"):
                                # Print a summary instead of full structure
                                if "data" in response_data:
                                    data = response_data["data"]
                                    if isinstance(data, dict):
                                        print(f"Section: {data.get('identifier', 'N/A')}")
                                        print(f"Label: {data.get('label', 'N/A')}")
                                        if "children" in data:
                                            print(f"Number of subsections: {len(data['children'])}")
                                    else:
                                        print("Full structure retrieved (too large to display)")
                                print("\n✅ Structure retrieved successfully")
                            else:
                                print(f"❌ Error: {response_data.get('error')}")
                                print(json.dumps(response_data, indent=2))

                print("\n" + "="*80)
                print("✅ All tests completed successfully!")
                print("="*80)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
