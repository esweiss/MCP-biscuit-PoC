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
        # Set session parameters for Row-Level Security
        logger.info(f"Biscuit token verification status: {facts.get('status') if facts else 'No token'}")

        # For RLS to work, we must extract the patient_name from the token
        # If no valid token or no patient name in token, RLS should block all access
        patient_name = None

        if facts and facts.get('status') in ['verified', 'verified_with_facts'] and 'facts' in facts:
            logger.info(f"Token verified, extracting patient name from facts")
            patient_names_facts = facts['facts'].get('patient_names', [])
            if patient_names_facts:
                # Extract from first fact if available
                if hasattr(patient_names_facts[0], 'terms') and patient_names_facts[0].terms:
                    patient_name = patient_names_facts[0].terms[0]
                    logger.info(f"Extracted patient name from token: {patient_name}")
                else:
                    patient_name = str(patient_names_facts[0])
                    logger.info(f"Using string representation: {patient_name}")
            else:
                logger.warning("Token verified but no patient_names facts found")
        else:
            logger.warning("No valid token provided or token verification failed")

        # Only set session parameter if we have a valid patient name from token
        if patient_name:
            logger.info(f"Setting session parameter for RLS: {patient_name}")
            try:
                # Set app.patient_name as expected by the RLS policy
                # Use the 3rd parameter = false to set for the current session only
                await conn.execute("SELECT set_config('app.patient_name', $1, false)", patient_name)
                logger.info("Successfully set app.patient_name session parameter")
            except Exception as e:
                logger.error(f"Could not set session parameter: {e}")
                # If the custom parameter doesn't exist, let's create it by setting it
                try:
                    # This should work even if the parameter isn't pre-defined
                    logger.info("Attempting to set parameter using direct assignment")
                    await conn.execute(f"SET app.patient_name = '{patient_name}'")
                    logger.info("Successfully set app.patient_name using SET")
                except Exception as e2:
                    logger.error(f"Both set_config and SET failed: {e2}")
                    raise Exception(f"Failed to set RLS parameter: {e2}")
        else:
            logger.warning("No patient name available - RLS will block all access")
            # Don't set any parameter - this will cause RLS to block access as expected

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

        After successfully fetching data, the token is attenuated with a sensitive_data=1
        fact to prevent subsequent calls to internet-accessible tools (data exfiltration prevention).

        Args:
            query: The SQL query to execute (must be read-only)
            conn_id: Connection ID previously obtained from the connect tool
            params: Parameters for the query (optional)

        Returns:
            Dictionary containing:
                - data: Query results as a list of dictionaries
                - token: Attenuated token with sensitive_data=1 fact (if data was fetched)
        """
        try:
            facts = authenticate_token(biscuit_token)
        except Exception as e:
            raise

        # Execute the query using the connection ID
        query_results = await execute_query(query, conn_id, params, facts)

        # If data was fetched, attenuate the token with sensitive_data=1
        # This prevents subsequent calls to internet-accessible tools
        if query_results and len(query_results) > 0:
            logger.info(f"Query returned {len(query_results)} rows - attenuating token with sensitive_data=1")

            try:
                # Get public key and initialize parser
                public_key_hex = os.getenv('BISCUIT_PUBLIC_KEY')
                parser = BiscuitParser(public_key_hex)

                # Attenuate the token
                attenuation_result = parser.attenuate_with_sensitive_data(biscuit_token)

                if attenuation_result["status"] == "attenuated":
                    attenuated_token = attenuation_result["attenuated_token"]
                    logger.info(f"Token attenuated: {attenuation_result['original_block_count']} -> {attenuation_result['attenuated_block_count']} blocks")

                    return {
                        "data": query_results,
                        "token": attenuated_token
                    }
                else:
                    logger.error(f"Token attenuation failed: {attenuation_result.get('error', 'Unknown error')}")
                    return {
                        "data": query_results,
                        "token": biscuit_token,
                        "error": f"Token attenuation failed: {attenuation_result.get('error', 'Unknown error')}"
                    }

            except Exception as e:
                logger.error(f"Exception during token attenuation: {e}")
                # Return results without token attenuation if it fails
                return {
                    "data": query_results,
                    "token": biscuit_token,
                    "error": f"Token attenuation exception: {str(e)}"
                }
        else:
            logger.info("Query returned no data - no token attenuation needed")
            return {
                "data": query_results,
                "token": biscuit_token
            }
        
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
