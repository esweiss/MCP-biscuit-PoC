# server/app.py
import os
import ssl
import dotenv
from server.logging_config import configure_logging, get_logger

dotenv.load_dotenv()
private_key = os.getenv('PRIVATE_KEY')

# Configure logging first thing to capture all subsequent log messages
log_level = os.environ.get("LOG_LEVEL", "DEBUG")
configure_logging(level=log_level)
logger = get_logger("app")

# Import MCP instance and other components after logging is configured
from server.config import mcp, global_db

# Import registration functions
from server.resources.schema import register_schema_resources
from server.resources.data import register_data_resources
from server.resources.extensions import register_extension_resources
from server.tools.connection import register_connection_tools
from server.tools.query import register_query_tools
from server.tools.viz import register_viz_tools
from server.prompts.natural_language import register_natural_language_prompts
from server.prompts.data_visualization import register_data_visualization_prompts

# Register tools and resources with the MCP server
logger.info("Registering resources and tools")
register_schema_resources()   # Schema-related resources (schemas, tables, columns)
register_extension_resources()
register_data_resources()     # Data-related resources (sample, rowcount, etc.)
register_connection_tools()   # Connection management tools
register_query_tools()
register_viz_tools()         # Visualization tools
register_natural_language_prompts()  # Natural language to SQL prompts
register_data_visualization_prompts() # Data visualization prompts


from contextlib import asynccontextmanager
from starlette.applications import Starlette
from starlette.routing import Mount
from server.tls_config import TLSConfig
from server.mtls_middleware import MTLSMiddleware

@asynccontextmanager
async def starlette_lifespan(app):
    logger.info("Starlette application starting up")
    yield
    logger.info("Starlette application shutting down, closing all database connections")
    await global_db.close()

async def run_server():
    """Run the server using FastMCP but bypassing anyio.run() to avoid event loop conflicts."""
    # Check if TLS should be enabled
    enable_tls = os.environ.get("ENABLE_TLS", "true").lower() == "true"

    if enable_tls:
        logger.info("Starting MCP server with HTTP transport (TLS handled by proxy)")
        # Call the async method directly instead of using mcp.run()
        await mcp.run_streamable_http_async()

    else:
        logger.info("Starting MCP server with SSE transport (no TLS)")
        # Call the async method directly instead of using mcp.run()
        await mcp.run_sse_async()

if __name__ == "__main__":
    import asyncio
    asyncio.run(run_server())
