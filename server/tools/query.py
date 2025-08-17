# server/tools/query.py
import pdb;
from server.config import mcp
from mcp.server.fastmcp import Context
from server.logging_config import get_logger
from biscuit_parser_module import BiscuitParser
import os

logger = get_logger("pg-mcp.tools.query")

async def execute_query(query: str, conn_id: str, params=None, facts=None, ctx=Context):
    """
    Execute a read-only SQL query against the PostgreSQL database.
    
    Args:
        query: The SQL query to execute (must be read-only)
        conn_id: Connection ID (required)
        params: Parameters for the query (optional)
        facts: Facts from the security token
        ctx: Optional request context
        
    Returns:
        Query results as a list of dictionaries
    """
    
    # Access the database from the request context
    # if ctx is not None and hasattr(ctx, 'request_context'):
    #     db = ctx.request_context.lifespan_context.get("db")
    # else:
    #     raise ValueError("Database connection not available in context or MCP state.")

    db = mcp.state["db"]
    if not db:
        raise ValueError("Database connection not available in MCP state.")
        
    logger.info(f"Executing query on connection ID {conn_id}: {query}")
    logger.info(f"\n params = {params}")
    logger.info(f"\n facts = {facts}")
    
    async with db.get_connection(conn_id) as conn:
        # Ensure we're in read-only mode
        await conn.execute("SET TRANSACTION READ ONLY")
        
        # Execute the query
        try:
            records = await conn.fetch(query, *(params or []))
            return [dict(record) for record in records]
        except Exception as e:
            # Log the error but don't couple to specific error types
            logger.error(f"Query execution error: {e}")
            raise

def authenticate_token(biscuit_token: str):
    public_key = os.getenv('BISCUIT_PUBLIC_KEY')

    # Initialize parser
    try:
        biscuit_parser = BiscuitParser(public_key)
    except Exception as e:
        logger.error(f"Error initializing parser: {e}")
        raise
    try:
        facts = biscuit_parser.verify_and_extract_facts(biscuit_token)
    except Exception as e:
        logger.error(f"Error invalid token: {e}")
        raise

    return facts


def register_query_tools():
    """Register database query tools with the MCP server."""
    logger.debug("Registering query tools")
    
    @mcp.tool()
    async def pg_query(biscuit_token: str, query: str, conn_id: str, params=None):
        """
        Execute a read-only SQL query against the PostgreSQL database.
        
        Args:
            query: The SQL query to execute (must be read-only)
            conn_id: Connection ID previously obtained from the connect tool
            params: Parameters for the query (optional)
            
        Returns:
            Query results as a list of dictionaries
        """
        try:
            facts = authenticate_token(biscuit_token)
        except Exception as e:
            raise

        # Execute the query using the connection ID 
        return await execute_query(query, conn_id, params, facts)
        
    @mcp.tool()
    async def pg_explain(query: str, conn_id: str, params=None):
        """
        Execute an EXPLAIN (FORMAT JSON) query to get PostgreSQL execution plan.
        
        Args:
            query: The SQL query to analyze
            conn_id: Connection ID previously obtained from the connect tool
            params: Parameters for the query (optional)
            
        Returns:
            Complete JSON-formatted execution plan
        """
        # Prepend EXPLAIN to the query
        explain_query = f"EXPLAIN (FORMAT JSON) {query}"
        
        # Execute the explain query
        result = await execute_query(explain_query, conn_id, params)
        
        # Return the complete result
        return result
