# server/database.py
import uuid
import urllib.parse
import asyncpg
from contextlib import asynccontextmanager
from mcp.server.fastmcp.utilities.logging import get_logger

logger = get_logger("pg-mcp.database")

class Database:
    def __init__(self):
        """Initialize the database manager with no default connections."""
        self._pools = {}  # Dictionary to store connection pools by connection ID
        self._connection_map = {}  # Map connection IDs to actual connection strings
        self._reverse_map = {}  # Map connection strings to their IDs

    def postgres_connection_to_uuid(self, connection_string, namespace=uuid.NAMESPACE_URL):
        """
        Convert a PostgreSQL connection string into a deterministic Version 5 UUID.
        Includes both connection credentials (netloc) and database name (path).
        
        Args:
            connection_string: Full PostgreSQL connection string
            namespace: UUID namespace (default is URL namespace)
            
        Returns:
            str: UUID representing the connection
        """
        # Parse the connection string
        parsed = urllib.parse.urlparse(connection_string)
        
        # Extract the netloc (user:password@host:port) and path (database name)
        # The path typically starts with a slash, so we strip it
        connection_id_string = parsed.netloc + parsed.path
        
        # Create a Version 5 UUID (SHA-1 based)
        result_uuid = uuid.uuid5(namespace, connection_id_string)
        
        return str(result_uuid)

    
    def register_connection(self, connection_string):
        """
        Register a connection string and return its UUID identifier.
        
        Args:
            connection_string: PostgreSQL connection string
            
        Returns:
            str: UUID identifier for this connection
        """
        if not connection_string.startswith("postgresql://"):
            connection_string = f"postgresql://{connection_string}"
            
        # Check if we already have this connection registered
        if connection_string in self._reverse_map:
            return self._reverse_map[connection_string]
            
        # Generate a new UUID
        conn_id = self.postgres_connection_to_uuid(connection_string)
        
        # Store mappings in both directions
        self._connection_map[conn_id] = connection_string
        self._reverse_map[connection_string] = conn_id
        
        logger.info(f"Registered new connection with ID {conn_id}")
        
        return conn_id
    
    def get_connection_string(self, conn_id):
        """Get the actual connection string for a connection ID."""
        if conn_id not in self._connection_map:
            raise ValueError(f"Unknown connection ID: {conn_id}")
            
        return self._connection_map[conn_id]
    
    async def initialize(self, conn_id):
        """Initialize a connection pool for the given connection ID."""
        if not conn_id:
            raise ValueError("Connection ID is required")
            
        if conn_id not in self._pools:
            # Get the actual connection string
            connection_string = self.get_connection_string(conn_id)
            
            logger.info(f"Creating new database connection pool for connection ID {conn_id}")
            self._pools[conn_id] = await asyncpg.create_pool(
                connection_string,
                min_size=2,
                max_size=10,
                command_timeout=60.0,
                # Read-only mode
                server_settings={"default_transaction_read_only": "true"}
            )
        
        return self
    
    @asynccontextmanager
    async def get_connection(self, conn_id):
        """Get a database connection from the pool for the given connection ID."""
        if not conn_id:
            raise ValueError("Connection ID is required")
            
        if conn_id not in self._pools:
            await self.initialize(conn_id)
        
        async with self._pools[conn_id].acquire() as conn:
            yield conn
    
    async def close(self, conn_id=None):
        """
        Close a specific or all database connection pools.
        
        Args:
            conn_id: If provided, close only this specific connection pool.
                    If None, close all connection pools.
        """
        if conn_id:
            if conn_id in self._pools:
                logger.info(f"Closing database connection pool for connection ID {conn_id}")
                await self._pools[conn_id].close()
                del self._pools[conn_id]
        else:
            # Close all connection pools
            logger.info("Closing all database connection pools")
            for id, pool in list(self._pools.items()):
                logger.info(f"Closing connection pool for ID {id}")
                await pool.close()
                del self._pools[id]