# server/tls_config.py
import ssl
import os
import logging
from typing import Optional, List
from pathlib import Path
try:
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)

class TLSConfig:
    """TLS configuration for MCP server with mutual authentication."""
    
    def __init__(self, cert_dir: str = "certs"):
        self.cert_dir = Path(cert_dir)
        self.authorized_clients = self._load_authorized_clients()
    
    def _load_authorized_clients(self) -> List[str]:
        """Load list of authorized client common names."""
        # For demo purposes, we'll hardcode authorized clients
        # In production, this would come from a configuration file or database
        return [
            "claude-client",
            "authorized-client",
        ]
    
    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for mTLS server."""
        try:
            # Create SSL context for server
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Load server certificate and key
            server_cert = self.cert_dir / "server-cert.pem"
            server_key = self.cert_dir / "server-key.pem"
            
            if not server_cert.exists() or not server_key.exists():
                raise FileNotFoundError(f"Server certificate files not found in {self.cert_dir}")
            
            context.load_cert_chain(str(server_cert), str(server_key))
            
            # Load CA certificate for client verification
            ca_cert = self.cert_dir / "ca-cert.pem"
            if not ca_cert.exists():
                raise FileNotFoundError(f"CA certificate not found: {ca_cert}")
            
            context.load_verify_locations(str(ca_cert))
            
            # Require client certificates
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Set up client certificate verification callback
            context.check_hostname = False  # We'll verify manually
            
            # NOTE: Python's ssl module doesn't support custom verification callbacks
            # like OpenSSL's set_verify. We'll need to implement client certificate
            # validation at the application level instead.
            
            logger.info(f"TLS context created with server cert: {server_cert}")
            logger.info(f"Authorized clients: {self.authorized_clients}")
            
            return context
            
        except Exception as e:
            logger.error(f"Failed to create TLS context: {e}")
            raise
    
    def verify_client_certificate(self, peercert_der: bytes) -> bool:
        """Verify client certificate is authorized."""
        try:
            import ssl
            import cryptography.x509
            from cryptography.x509.oid import NameOID
            
            # Parse the DER-encoded certificate
            cert = cryptography.x509.load_der_x509_certificate(peercert_der)
            
            # Extract the common name
            try:
                common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                logger.info(f"Client certificate CN: {common_name}")
                
                # Check if client is authorized
                if common_name in self.authorized_clients:
                    logger.info(f"Client '{common_name}' is authorized")
                    return True
                else:
                    logger.warning(f"Client '{common_name}' is not in authorized list: {self.authorized_clients}")
                    return False
                    
            except (IndexError, AttributeError) as e:
                logger.error(f"Could not extract CN from client certificate: {e}")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying client certificate: {e}")
            return False
    
    def get_client_identity(self, peercert_der: bytes) -> Optional[str]:
        """Extract client identity from certificate."""
        try:
            import cryptography.x509
            from cryptography.x509.oid import NameOID
            
            cert = cryptography.x509.load_der_x509_certificate(peercert_der)
            common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            return common_name
            
        except Exception as e:
            logger.error(f"Error extracting client identity: {e}")
            return None