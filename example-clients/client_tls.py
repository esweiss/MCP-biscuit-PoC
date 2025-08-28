# example-clients/client_tls.py
import ssl
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

class ClientTLS:
    """TLS configuration for MCP client with mutual authentication."""
    
    def __init__(self, cert_dir: str = "certs", client_name: str = "claude-client"):
        self.cert_dir = Path(cert_dir)
        self.client_name = client_name
        self.authorized_servers = self._load_authorized_servers()
    
    def _load_authorized_servers(self) -> list[str]:
        """Load list of authorized server common names."""
        return ["mcp-server"]
    
    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for mTLS client."""
        try:
            # Create SSL context for client
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # Load client certificate and key
            client_cert = self.cert_dir / f"{self.client_name}-cert.pem"
            client_key = self.cert_dir / f"{self.client_name}-key.pem"
            
            if not client_cert.exists() or not client_key.exists():
                raise FileNotFoundError(f"Client certificate files not found: {client_cert}, {client_key}")
            
            context.load_cert_chain(str(client_cert), str(client_key))
            
            # Load CA certificate for server verification
            ca_cert = self.cert_dir / "ca-cert.pem"
            if not ca_cert.exists():
                raise FileNotFoundError(f"CA certificate not found: {ca_cert}")
            
            context.load_verify_locations(str(ca_cert))
            
            # Verify server certificate
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False  # We'll verify manually
            
            logger.info(f"Client TLS context created with cert: {client_cert}")
            logger.info(f"Authorized servers: {self.authorized_servers}")
            
            return context
            
        except Exception as e:
            logger.error(f"Failed to create client TLS context: {e}")
            raise
    
    def verify_server_certificate(self, peercert_der: bytes) -> bool:
        """Verify server certificate is authorized."""
        try:
            import cryptography.x509
            from cryptography.x509.oid import NameOID
            
            # Parse the DER-encoded certificate
            cert = cryptography.x509.load_der_x509_certificate(peercert_der)
            
            # Extract the common name
            try:
                common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                logger.info(f"Server certificate CN: {common_name}")
                
                # Check if server is authorized
                if common_name in self.authorized_servers:
                    logger.info(f"Server '{common_name}' is authorized")
                    return True
                else:
                    logger.warning(f"Server '{common_name}' is not in authorized list: {self.authorized_servers}")
                    return False
                    
            except (IndexError, AttributeError) as e:
                logger.error(f"Could not extract CN from server certificate: {e}")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying server certificate: {e}")
            return False