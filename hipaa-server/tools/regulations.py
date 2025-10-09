#!/usr/bin/env python3
"""
HIPAA Regulations Tools

Provides tools for fetching and monitoring HIPAA regulations from eCFR.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
import httpx

import sys
from pathlib import Path

# Add parent directory to path
parent_dir = Path(__file__).parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from config import mcp, ECFR_API_URL, CACHE_FILE

# Import BiscuitParser at module level (same as database server)
import os
parent_project_dir = Path(__file__).parent.parent.parent
if str(parent_project_dir) not in sys.path:
    sys.path.insert(0, str(parent_project_dir))

from biscuit_parser_module import BiscuitParser

logger = logging.getLogger(__name__)


class RegulationsCache:
    """Manages caching and change detection for HIPAA regulations."""

    def __init__(self, cache_file: Path):
        self.cache_file = cache_file
        self.metadata_file = cache_file.parent / "metadata.json"

    def load_cached_data(self) -> Optional[Dict[str, Any]]:
        """Load cached regulations data."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load cached data: {e}")
        return None

    def save_data(self, data: Dict[str, Any]) -> None:
        """Save regulations data to cache."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)

            # Save metadata
            metadata = {
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "content_hash": self._calculate_hash(data),
                "source_url": ECFR_API_URL
            }

            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            logger.info("Cached regulations data updated")
        except Exception as e:
            logger.error(f"Failed to save data: {e}")

    def get_metadata(self) -> Optional[Dict[str, Any]]:
        """Get cache metadata."""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load metadata: {e}")
        return None

    def _calculate_hash(self, data: Dict[str, Any]) -> str:
        """Calculate hash of regulations data."""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()

    def has_changed(self, new_data: Dict[str, Any]) -> bool:
        """Check if regulations data has changed."""
        metadata = self.get_metadata()
        if not metadata:
            return True

        old_hash = metadata.get("content_hash")
        new_hash = self._calculate_hash(new_data)

        return old_hash != new_hash


# Initialize cache
cache = RegulationsCache(CACHE_FILE)


def authenticate_token(biscuit_token: Optional[str]) -> Dict[str, Any]:
    """
    Authenticate and extract facts from Biscuit token.

    Simplified version that returns facts dict directly like database server.

    Args:
        biscuit_token: Base64-encoded Biscuit token

    Returns:
        Dictionary with facts and verification status
    """
    if not biscuit_token:
        logger.warning("No Biscuit token provided")
        return {
            "status": "no_token",
            "authenticated": False,
            "error": "No Biscuit token provided"
        }

    try:
        # Get public key from environment
        public_key = os.getenv('BISCUIT_PUBLIC_KEY')
        if not public_key:
            logger.error("No BISCUIT_PUBLIC_KEY in environment")
            return {
                "status": "no_public_key",
                "authenticated": False,
                "error": "No BISCUIT_PUBLIC_KEY configured"
            }

        # Initialize parser and verify - same as database server
        try:
            parser = BiscuitParser(public_key)
        except Exception as e:
            logger.error(f"Error initializing BiscuitParser: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "status": "parser_init_error",
                "authenticated": False,
                "error": f"Parser initialization failed: {str(e)}"
            }

        try:
            facts = parser.verify_and_extract_facts(biscuit_token)
        except Exception as e:
            logger.error(f"Error verifying token: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "status": "verification_error",
                "authenticated": False,
                "error": f"Token verification failed: {str(e)}"
            }

        # Return facts dict with authenticated flag
        if facts.get("status") == "verified_with_facts":
            logger.info("✅ Biscuit token verified successfully")
            return {
                **facts,
                "authenticated": True
            }
        else:
            logger.warning(f"❌ Token verification returned status: {facts.get('status')}")
            return {
                **facts,
                "authenticated": False,
                "error": f"Verification status: {facts.get('status')}"
            }

    except Exception as e:
        logger.error(f"❌ Unexpected token authentication error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            "status": "unexpected_error",
            "authenticated": False,
            "error": f"Authentication error: {str(e)}"
        }


@mcp.tool()
async def check_hipaa_updates(biscuit_token: str) -> str:
    """
    Check if there have been updates to HIPAA regulations (45 CFR).

    This tool fetches the latest HIPAA regulations from the eCFR API and compares
    them with the cached version to detect any changes.

    Args:
        biscuit_token: Base64-encoded Biscuit authorization token

    Returns:
        JSON string with update status and details
    """
    # Authenticate token
    auth_result = authenticate_token(biscuit_token)

    if not auth_result["authenticated"]:
        return json.dumps({
            "success": False,
            "error": "Authentication failed",
            "details": auth_result.get("error", "Invalid token")
        }, indent=2)

    logger.info("✅ Token authenticated, checking for HIPAA updates")

    try:
        # Fetch latest data from eCFR
        async with httpx.AsyncClient(timeout=30.0) as client:
            logger.info(f"📥 Fetching regulations from {ECFR_API_URL}")
            response = await client.get(ECFR_API_URL)
            response.raise_for_status()
            new_data = response.json()

        # Load cached data
        cached_data = cache.load_cached_data()
        metadata = cache.get_metadata()

        # Check for changes
        has_changed = cache.has_changed(new_data)

        if has_changed:
            logger.info("📝 Changes detected in HIPAA regulations")
            cache.save_data(new_data)

            return json.dumps({
                "success": True,
                "has_updates": True,
                "message": "Changes detected in HIPAA regulations (45 CFR Title 45)",
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "previous_update": metadata.get("last_updated") if metadata else "Never",
                "changes_summary": "Regulations content has been modified"
            }, indent=2)
        else:
            logger.info("✅ No changes detected in HIPAA regulations")

            return json.dumps({
                "success": True,
                "has_updates": False,
                "message": "No changes detected in HIPAA regulations (45 CFR Title 45)",
                "last_checked": datetime.now(timezone.utc).isoformat(),
                "last_update": metadata.get("last_updated") if metadata else "Unknown"
            }, indent=2)

    except httpx.HTTPError as e:
        logger.error(f"❌ HTTP error fetching regulations: {e}")
        return json.dumps({
            "success": False,
            "error": "Failed to fetch regulations from eCFR",
            "details": str(e)
        }, indent=2)

    except Exception as e:
        logger.error(f"❌ Error checking updates: {e}")
        return json.dumps({
            "success": False,
            "error": "Failed to check for updates",
            "details": str(e)
        }, indent=2)


@mcp.tool()
async def get_hipaa_structure(biscuit_token: str, section: Optional[str] = None) -> str:
    """
    Get the structure of HIPAA regulations (45 CFR).

    Returns the hierarchical structure of the regulations, optionally filtered
    to a specific section.

    Args:
        biscuit_token: Base64-encoded Biscuit authorization token
        section: Optional section number to filter (e.g., "160" for HIPAA Security Rule)

    Returns:
        JSON string with regulations structure
    """
    # Authenticate token
    auth_result = authenticate_token(biscuit_token)

    if not auth_result["authenticated"]:
        return json.dumps({
            "success": False,
            "error": "Authentication failed",
            "details": auth_result.get("error", "Invalid token")
        }, indent=2)

    logger.info(f"✅ Token authenticated, retrieving HIPAA structure{f' for section {section}' if section else ''}")

    try:
        # Load cached data or fetch from API
        data = cache.load_cached_data()

        if not data:
            # Fetch from API if no cache
            async with httpx.AsyncClient(timeout=30.0) as client:
                logger.info(f"📥 Fetching regulations from {ECFR_API_URL}")
                response = await client.get(ECFR_API_URL)
                response.raise_for_status()
                data = response.json()
                cache.save_data(data)

        # Filter to specific section if requested
        if section:
            # Navigate the structure to find the requested section
            # This is simplified - actual structure may vary
            filtered_data = _filter_section(data, section)

            if not filtered_data:
                return json.dumps({
                    "success": False,
                    "error": f"Section {section} not found in regulations"
                }, indent=2)

            return json.dumps({
                "success": True,
                "section": section,
                "data": filtered_data
            }, indent=2)
        else:
            # Return full structure (may be large)
            return json.dumps({
                "success": True,
                "data": data
            }, indent=2)

    except Exception as e:
        logger.error(f"❌ Error retrieving structure: {e}")
        return json.dumps({
            "success": False,
            "error": "Failed to retrieve regulations structure",
            "details": str(e)
        }, indent=2)


def _filter_section(data: Dict[str, Any], section: str) -> Optional[Dict[str, Any]]:
    """Helper function to filter regulations data to a specific section."""
    # This is a simplified implementation
    # The actual eCFR JSON structure may require more sophisticated filtering

    try:
        # Try to find section in the structure
        if "children" in data:
            for child in data["children"]:
                if child.get("identifier") == section or child.get("label") == section:
                    return child

                # Recursively search children
                result = _filter_section(child, section)
                if result:
                    return result

        return None
    except Exception as e:
        logger.error(f"Error filtering section: {e}")
        return None


def register_regulations_tools():
    """Register regulations monitoring tools."""
    logger.info("📋 Regulations tools registered")


if __name__ == "__main__":
    # This allows the module to be imported without issues
    pass
