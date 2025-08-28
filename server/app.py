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
    """Run the server using hypercorn for proper mTLS support."""
    from hypercorn.config import Config
    from hypercorn.asyncio import serve
    
    # Check if TLS should be enabled
    enable_tls = os.environ.get("ENABLE_TLS", "true").lower() == "true"
    
    if enable_tls:
        logger.info("Starting MCP server with TLS and mTLS using Hypercorn")
        
        # Initialize TLS configuration
        tls_config = TLSConfig()
        ssl_context = tls_config.create_ssl_context()
        
        app = Starlette(
            routes=[Mount('/', app=mcp.sse_app())],
            lifespan=starlette_lifespan
        )
        
        # Add mTLS middleware
        app.add_middleware(MTLSMiddleware, tls_config=tls_config)
        
        # Configure hypercorn with SSL
        config = Config()
        config.bind = ["0.0.0.0:8443"]
        
        # Use our custom SSL context with client certificate verification
        config.ssl = ssl_context
        
        # Enable HTTP/2 and HTTP/1.1
        config.alpn_protocols = ["h2", "http/1.1"]
        
        # Set log level
        config.loglevel = log_level.lower()
        config.access_log_format = "%(h)s - - [%(t)s] \"%(r)s\" %(s)s %(b)s"
        
        logger.info("Hypercorn server configured with mTLS SSL context")
        logger.info(f"Server starting on https://0.0.0.0:8443")
        
        # Start the server
        await serve(app, config)
        
    else:
        logger.info("Starting MCP server with SSE transport (no TLS) using Hypercorn")
        
        app = Starlette(
            routes=[Mount('/', app=mcp.sse_app())],
            lifespan=starlette_lifespan
        )
        
        # Configure hypercorn without TLS
        config = Config()
        config.bind = ["0.0.0.0:8000"]
        config.loglevel = log_level.lower()
        
        logger.info("Hypercorn server starting on http://0.0.0.0:8000")
        
        # Start the server
        await serve(app, config)

if __name__ == "__main__":
    import asyncio
    asyncio.run(run_server())
