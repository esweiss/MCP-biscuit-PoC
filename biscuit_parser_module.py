"""
Biscuit Token Parser Module

A Python module for parsing, authenticating, and analyzing Biscuit authorization tokens.
Provides the core BiscuitParser class for programmatic use.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import biscuit_auth as biscuit


class BiscuitParser:
    """
    A class for parsing and authenticating Biscuit authorization tokens.
    
    This class provides methods to:
    - Parse tokens with or without cryptographic verification
    - Perform authorization checks against user/resource/operation combinations
    - Extract token metadata and contents
    - Analyze tokens comprehensively
    
    Args:
        public_key_hex (Optional[str]): Public key in hex format for token verification
    """
    
    def __init__(self, public_key_hex: Optional[str] = None):
        """Initialize parser with optional public key for verification."""
        self.public_key = None
        if public_key_hex:
            self.public_key = biscuit.PublicKey.from_hex(public_key_hex)
    
    def set_public_key(self, public_key_hex: str) -> None:
        """Set or update the public key for verification."""
        self.public_key = biscuit.PublicKey.from_hex(public_key_hex)
    
    def parse_unverified(self, token_b64: str) -> Dict[str, Any]:
        """
        Parse token without cryptographic verification for inspection.
        
        Args:
            token_b64 (str): Base64-encoded biscuit token
            
        Returns:
            Dict[str, Any]: Parsing result with status, block count, and metadata
        """
        try:
            unverified_token = biscuit.UnverifiedBiscuit.from_base64(token_b64)
            
            return {
                "status": "parsed_unverified",
                "block_count": unverified_token.block_count(),
                "revocation_ids": unverified_token.revocation_ids,
                "token_length": len(token_b64),
                "raw_token": token_b64
            }
        except Exception as e:
            return {
                "status": "parse_error",
                "error": str(e),
                "token_length": len(token_b64)
            }
    
    def verify_and_parse(self, token_b64: str) -> Dict[str, Any]:
        """
        Verify token cryptographically and parse its contents.
        
        Args:
            token_b64 (str): Base64-encoded biscuit token
            
        Returns:
            Dict[str, Any]: Verification result with status and token metadata
        """
        if not self.public_key:
            return {
                "status": "verification_error",
                "error": "No public key provided for verification"
            }
        
        try:
            # Parse and verify the token
            verified_token = biscuit.Biscuit.from_base64(token_b64, self.public_key)
            
            # Get basic token info
            unverified_info = self.parse_unverified(token_b64)
            
            result = {
                "status": "verified",
                "verification": "SUCCESS",
                "block_count": unverified_info["block_count"],
                "revocation_ids": unverified_info["revocation_ids"],
                "token_length": unverified_info["token_length"]
            }
            
            return result
            
        except Exception as e:
            return {
                "status": "verification_failed",
                "error": str(e),
                "unverified_info": self.parse_unverified(token_b64)
            }
    
    def authorize_token(self, token_b64: str, user_id: str, resource: str, 
                       operation: str, current_time: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Authorize a token for specific user, resource, and operation.
        
        Args:
            token_b64 (str): Base64-encoded biscuit token
            user_id (str): User ID to authorize
            resource (str): Resource to access
            operation (str): Operation to perform
            current_time (Optional[datetime]): Current time for time-based checks
            
        Returns:
            Dict[str, Any]: Authorization result with status and debugging information
        """
        if not self.public_key:
            return {
                "status": "authorization_error",
                "error": "No public key provided for verification"
            }
        
        if not current_time:
            current_time = datetime.now(timezone.utc)
        
        try:
            # Parse and verify the token
            verified_token = biscuit.Biscuit.from_base64(token_b64, self.public_key)
            
            # Create authorizer with current context
            current_timestamp = int(current_time.timestamp())
            authorizer = biscuit.Authorizer(f"""
                time({current_timestamp});
                resource("{resource}");
                operation("{operation}");
                request_user("{user_id}");
                
                // Allow if token grants permission
                allow if user("{user_id}"), resource("{resource}"), operation("{operation}");
                
                // Allow with role-based rules
                allow if user("{user_id}"), role($role), resource("{resource}"), 
                         allow("{user_id}", "{resource}", "{operation}");
                
                // Time-based authorization
                allow if user("{user_id}"), resource("{resource}"), operation("{operation}"),
                         time($time), expiry($exp), $time <= $exp;
            """)
            
            # Add the token to the authorizer
            authorizer.add_token(verified_token)
            
            # Perform authorization
            auth_result = authorizer.authorize()
            
            # Query for debugging information
            try:
                user_facts = authorizer.query(biscuit.Rule('data($u) <- user($u)'))
                resource_facts = authorizer.query(biscuit.Rule('data($r) <- resource($r)'))
                operation_facts = authorizer.query(biscuit.Rule('data($o) <- operation($o)'))
                role_facts = authorizer.query(biscuit.Rule('data($role) <- role($role)'))
                expiry_facts = authorizer.query(biscuit.Rule('data($exp) <- expiry($exp)'))
            except:
                user_facts = []
                resource_facts = []
                operation_facts = []
                role_facts = []
                expiry_facts = []
            
            return {
                "status": "authorization_complete",
                "authorized": auth_result == 0,
                "auth_code": auth_result,
                "user_id": user_id,
                "resource": resource,
                "operation": operation,
                "current_time": current_time.isoformat(),
                "facts": {
                    "users": user_facts,
                    "resources": resource_facts,
                    "operations": operation_facts,
                    "roles": role_facts,
                    "expiry": expiry_facts
                }
            }
            
        except Exception as e:
            return {
                "status": "authorization_error",
                "error": str(e),
                "user_id": user_id,
                "resource": resource,
                "operation": operation
            }
    
    def analyze_token(self, token_b64: str) -> Dict[str, Any]:
        """
        Comprehensive token analysis including verification and content extraction.
        
        Args:
            token_b64 (str): Base64-encoded biscuit token
            
        Returns:
            Dict[str, Any]: Complete analysis result with parsing and verification info
        """
        result = {
            "token_analysis": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "token_length": len(token_b64)
            }
        }
        
        # Step 1: Parse without verification
        unverified_result = self.parse_unverified(token_b64)
        result["unverified_parse"] = unverified_result
        
        # Step 2: Verify if public key is available
        if self.public_key:
            verified_result = self.verify_and_parse(token_b64)
            result["verification"] = verified_result
        else:
            result["verification"] = {
                "status": "skipped",
                "reason": "No public key provided"
            }
        
        return result
    
    def batch_analyze(self, tokens: List[str]) -> Dict[str, Any]:
        """
        Analyze multiple tokens in batch.
        
        Args:
            tokens (List[str]): List of base64-encoded biscuit tokens
            
        Returns:
            Dict[str, Any]: Batch analysis results for all tokens
        """
        results = []
        
        for i, token in enumerate(tokens):
            token_result = self.analyze_token(token)
            token_result["token_index"] = i
            results.append(token_result)
        
        return {
            "batch_analysis": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "token_count": len(tokens),
                "results": results
            }
        }
    
    def is_token_valid(self, token_b64: str) -> bool:
        """
        Quick check if token is cryptographically valid.
        
        Args:
            token_b64 (str): Base64-encoded biscuit token
            
        Returns:
            bool: True if token is valid, False otherwise
        """
        if not self.public_key:
            return False
        
        try:
            biscuit.Biscuit.from_base64(token_b64, self.public_key)
            return True
        except:
            return False
    
    def get_token_metadata(self, token_b64: str) -> Dict[str, Any]:
        """
        Extract basic metadata from token without full parsing.
        
        Args:
            token_b64 (str): Base64-encoded biscuit token
            
        Returns:
            Dict[str, Any]: Basic token metadata
        """
        try:
            unverified_token = biscuit.UnverifiedBiscuit.from_base64(token_b64)
            return {
                "valid": True,
                "block_count": unverified_token.block_count(),
                "revocation_ids": unverified_token.revocation_ids,
                "token_length": len(token_b64)
            }
        except:
            return {
                "valid": False,
                "token_length": len(token_b64)
            }
    
    def verify_and_extract_facts(self, token_b64: str, current_time: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Verify token cryptographically and extract all facts without authorization.
        
        Args:
            token_b64 (str): Base64-encoded biscuit token
            current_time (Optional[datetime]): Current time for time-based facts
            
        Returns:
            Dict[str, Any]: Verification result with extracted facts
        """
        if not self.public_key:
            return {
                "status": "verification_error",
                "error": "No public key provided for verification"
            }
        
        if not current_time:
            current_time = datetime.now(timezone.utc)
        
        try:
            verified_token = biscuit.Biscuit.from_base64(token_b64, self.public_key)
            
            current_timestamp = int(current_time.timestamp())
            authorizer = biscuit.Authorizer(f"time({current_timestamp});")
            
            authorizer.add_token(verified_token)
            
            facts = {}
            try:
                facts["users"] = authorizer.query(biscuit.Rule('data($u) <- user($u)'))
                facts["resources"] = authorizer.query(biscuit.Rule('data($r) <- resource($r)'))
                facts["operations"] = authorizer.query(biscuit.Rule('data($o) <- operation($o)'))
                facts["roles"] = authorizer.query(biscuit.Rule('data($role) <- role($role)'))
                facts["expiry"] = authorizer.query(biscuit.Rule('data($exp) <- expiry($exp)'))
                facts["allow"] = authorizer.query(biscuit.Rule('data($u, $r, $o) <- allow($u, $r, $o)'))
                facts["time"] = authorizer.query(biscuit.Rule('data($t) <- time($t)'))
                # Add patient_name fact query for RLS support
                facts["patient_names"] = authorizer.query(biscuit.Rule('data($name) <- patient_name($name)'))
                # Add mTLS-specific fact queries
                facts["mtls_clients"] = authorizer.query(biscuit.Rule('data($client) <- mtls_client($client)'))
                facts["mtls_audiences"] = authorizer.query(biscuit.Rule('data($audience) <- mtls_audience($audience)'))
                facts["attestation_times"] = authorizer.query(biscuit.Rule('data($time) <- attestation_time($time)'))
            except Exception as query_error:
                facts["query_error"] = str(query_error)
            
            unverified_info = self.parse_unverified(token_b64)
            
            return {
                "status": "verified_with_facts",
                "verification": "SUCCESS",
                "block_count": unverified_info["block_count"],
                "revocation_ids": unverified_info["revocation_ids"],
                "token_length": unverified_info["token_length"],
                "current_time": current_time.isoformat(),
                "facts": facts
            }
            
        except Exception as e:
            return {
                "status": "verification_failed",
                "error": str(e),
                "unverified_info": self.parse_unverified(token_b64)
            }
    
    def validate_mtls_attestation(self, token_b64: str, expected_client_identity: str, 
                                  expected_server_identity: str, current_time: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Validate mTLS attestation in Biscuit token against expected identities.
        
        Args:
            token_b64 (str): Base64-encoded biscuit token
            expected_client_identity (str): Expected mTLS client identity (from certificate CN)
            expected_server_identity (str): Expected mTLS server identity (server's certificate CN) 
            current_time (Optional[datetime]): Current time for validation
            
        Returns:
            Dict[str, Any]: Validation result with detailed status
        """
        if not self.public_key:
            return {
                "status": "validation_error",
                "error": "No public key provided for verification",
                "mtls_validation": False
            }
        
        if not current_time:
            current_time = datetime.now(timezone.utc)
        
        try:
            # First verify the token and extract facts
            facts_result = self.verify_and_extract_facts(token_b64, current_time)
            
            if facts_result["status"] != "verified_with_facts":
                return {
                    "status": "token_verification_failed",
                    "error": "Token verification failed",
                    "mtls_validation": False,
                    "verification_details": facts_result
                }
            
            facts = facts_result["facts"]
            
            # Extract mTLS attestation facts
            mtls_clients = facts.get("mtls_clients", [])
            mtls_audiences = facts.get("mtls_audiences", [])
            attestation_times = facts.get("attestation_times", [])
            
            # Validation results
            validation_result = {
                "status": "mtls_validation_complete",
                "mtls_validation": True,  # Will be set to False if any check fails
                "expected_client": expected_client_identity,
                "expected_server": expected_server_identity,
                "found_clients": mtls_clients,
                "found_audiences": mtls_audiences,
                "found_attestation_times": attestation_times,
                "validation_details": {}
            }
            
            # Check 1: Client identity validation
            client_valid = False
            for client_fact in mtls_clients:
                # Handle different fact formats
                if isinstance(client_fact, dict) and "client" in client_fact:
                    # Legacy dict format
                    if client_fact["client"] == expected_client_identity:
                        client_valid = True
                        break
                elif hasattr(client_fact, 'terms') and len(client_fact.terms) > 0:
                    # Handle Fact object with terms (biscuit-python format)
                    if client_fact.terms[0] == expected_client_identity:
                        client_valid = True
                        break
                elif hasattr(client_fact, 'data') and len(client_fact.data) > 0:
                    # Handle data("value") format from some biscuit versions
                    if client_fact.data[0] == expected_client_identity:
                        client_valid = True
                        break
                elif str(client_fact).strip('"') == expected_client_identity:
                    # Handle string format fallback
                    client_valid = True
                    break
            
            validation_result["validation_details"]["client_identity_valid"] = client_valid
            if not client_valid:
                validation_result["mtls_validation"] = False
                validation_result["validation_details"]["client_identity_error"] = f"Expected client '{expected_client_identity}' not found in token"
            
            # Check 2: Server audience validation
            audience_valid = False
            for audience_fact in mtls_audiences:
                # Handle different fact formats
                if isinstance(audience_fact, dict) and "audience" in audience_fact:
                    # Legacy dict format
                    if audience_fact["audience"] == expected_server_identity:
                        audience_valid = True
                        break
                elif hasattr(audience_fact, 'terms') and len(audience_fact.terms) > 0:
                    # Handle Fact object with terms (biscuit-python format)
                    if audience_fact.terms[0] == expected_server_identity:
                        audience_valid = True
                        break
                elif hasattr(audience_fact, 'data') and len(audience_fact.data) > 0:
                    # Handle data("value") format from some biscuit versions
                    if audience_fact.data[0] == expected_server_identity:
                        audience_valid = True
                        break
                elif str(audience_fact).strip('"') == expected_server_identity:
                    # Handle string format fallback
                    audience_valid = True
                    break
            
            validation_result["validation_details"]["server_audience_valid"] = audience_valid
            if not audience_valid:
                validation_result["mtls_validation"] = False
                validation_result["validation_details"]["server_audience_error"] = f"Expected server audience '{expected_server_identity}' not found in token"
            
            # Check 3: Attestation time validation (ensure it's recent)
            attestation_time_valid = True
            current_timestamp = int(current_time.timestamp())
            max_attestation_age = 3600  # 1 hour max age
            
            if attestation_times:
                for time_fact in attestation_times:
                    attestation_timestamp = None
                    
                    # Handle different fact formats
                    if isinstance(time_fact, dict) and "time" in time_fact:
                        # Legacy dict format
                        attestation_timestamp = time_fact["time"]
                    elif hasattr(time_fact, 'terms') and len(time_fact.terms) > 0:
                        # Handle Fact object with terms (biscuit-python format)
                        attestation_timestamp = int(time_fact.terms[0])
                    elif hasattr(time_fact, 'data') and len(time_fact.data) > 0:
                        # Handle data(value) format from some biscuit versions
                        attestation_timestamp = int(time_fact.data[0])
                    elif isinstance(time_fact, (int, str)):
                        # Handle direct numeric format
                        attestation_timestamp = int(time_fact)
                    
                    if attestation_timestamp:
                        age = current_timestamp - attestation_timestamp
                        if age > max_attestation_age:
                            attestation_time_valid = False
                            validation_result["validation_details"]["attestation_time_error"] = f"Attestation too old: {age} seconds"
                            break
            else:
                attestation_time_valid = False
                validation_result["validation_details"]["attestation_time_error"] = "No attestation timestamp found"
            
            validation_result["validation_details"]["attestation_time_valid"] = attestation_time_valid
            if not attestation_time_valid:
                validation_result["mtls_validation"] = False
            
            # Extract user information from primary block for additional context
            users = facts.get("users", [])
            if users:
                validation_result["primary_user"] = users[0].get("u") if isinstance(users[0], dict) else None
            
            return validation_result
            
        except Exception as e:
            return {
                "status": "validation_error", 
                "error": str(e),
                "mtls_validation": False
            }


class BiscuitAuthorizationError(Exception):
    """Exception raised when biscuit authorization fails."""
    pass


class BiscuitVerificationError(Exception):
    """Exception raised when biscuit verification fails."""
    pass


class BiscuitParseError(Exception):
    """Exception raised when biscuit parsing fails."""
    pass