# server/mtls_middleware.py
import logging
import ssl
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from server.tls_config import TLSConfig

logger = logging.getLogger(__name__)

class MTLSMiddleware(BaseHTTPMiddleware):
    """Middleware to verify client certificates in mTLS connections."""
    
    def __init__(self, app, tls_config: TLSConfig):
        super().__init__(app)
        self.tls_config = tls_config
    
    async def dispatch(self, request: Request, call_next):
        """Verify client certificate before processing request."""
        try:
            # Get the client certificate from the connection
            scope = request.scope
            
            # Try multiple methods to get the client certificate
            # Hypercorn should provide better access to client certificates
            peer_cert_der = None
            
            # Method 1: Check ASGI extensions (hypercorn should populate this)
            if "extensions" in scope:
                extensions = scope["extensions"]
                logger.debug(f"ASGI extensions available: {list(extensions.keys())}")
                
                if "tls" in extensions:
                    tls_info = extensions["tls"]
                    logger.debug(f"TLS info keys: {list(tls_info.keys()) if isinstance(tls_info, dict) else type(tls_info)}")
                    
                    if isinstance(tls_info, dict):
                        peer_cert_der = tls_info.get("peercert") or tls_info.get("peer_cert") or tls_info.get("client_cert")
                        if peer_cert_der:
                            logger.info("Client certificate found in ASGI TLS extensions")
                    else:
                        # TLS info might be an SSL object
                        try:
                            if hasattr(tls_info, 'getpeercert'):
                                peer_cert_der = tls_info.getpeercert(binary_form=True)
                                if peer_cert_der:
                                    logger.info("Client certificate found via TLS info SSL object")
                        except Exception as e:
                            logger.debug(f"Failed to get cert from TLS info object: {e}")
            
            # Method 2: Try to get from transport (fallback for hypercorn)
            if not peer_cert_der:
                transport = scope.get("transport")
                if transport:
                    # Try different SSL object access methods
                    ssl_object = None
                    if hasattr(transport, "_ssl_object"):
                        ssl_object = transport._ssl_object
                    elif hasattr(transport, "ssl_object"):
                        ssl_object = transport.ssl_object
                    elif hasattr(transport, "get_extra_info"):
                        ssl_object = transport.get_extra_info("ssl_object")
                    
                    if ssl_object:
                        try:
                            peer_cert_der = ssl_object.getpeercert(binary_form=True)
                            if peer_cert_der:
                                logger.info("Client certificate found in transport SSL object")
                            else:
                                logger.warning("No client certificate in transport SSL object")
                        except Exception as e:
                            logger.warning(f"Failed to get peer certificate from transport: {e}")
            
            # Method 3: Check if client certificate is in scope directly (some servers put it here)
            if not peer_cert_der and "client" in scope:
                client_info = scope["client"]
                if isinstance(client_info, dict) and "peercert" in client_info:
                    peer_cert_der = client_info["peercert"]
                    if peer_cert_der:
                        logger.info("Client certificate found in client scope")
                        
            # Debug logging if certificate not found
            if not peer_cert_der:
                headers = dict(request.headers)
                logger.debug(f"Request headers: {list(headers.keys())}")
                logger.debug(f"Request scope keys: {list(scope.keys())}")
                transport = scope.get("transport")
                if transport:
                    logger.debug(f"Transport type: {type(transport)}")
                    logger.debug(f"Transport attributes: {[attr for attr in dir(transport) if not attr.startswith('_')]}")
            
            # If we have a client certificate, verify it
            if peer_cert_der:
                # Verify the client certificate
                if not self.tls_config.verify_client_certificate(peer_cert_der):
                    logger.warning("Client certificate verification failed - unauthorized client")
                    return JSONResponse(
                        status_code=403,
                        content={"error": "Client certificate not authorized"}
                    )
                
                # Get client identity for logging
                client_identity = self.tls_config.get_client_identity(peer_cert_der)
                if client_identity:
                    logger.info(f"Authorized client connected: {client_identity}")
                    # Store client identity in request state for later use
                    request.state.client_identity = client_identity
                else:
                    logger.warning("Could not extract client identity from certificate")
                    return JSONResponse(
                        status_code=403,
                        content={"error": "Invalid client certificate"}
                    )
            else:
                # No client certificate found - this shouldn't happen with CERT_REQUIRED
                logger.error("No client certificate found despite ssl.CERT_REQUIRED setting")
                return JSONResponse(
                    status_code=401,
                    content={"error": "Client certificate required"}
                )
            
            # Continue with the request
            response = await call_next(request)
            return response
            
        except Exception as e:
            logger.error(f"Error in mTLS middleware: {e}", exc_info=True)
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error during certificate verification"}
            )