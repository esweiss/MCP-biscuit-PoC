#!/usr/bin/env python3
"""
Biscuit Token Parser CLI

Command-line interface for parsing, authenticating, and analyzing Biscuit authorization tokens.
Uses the biscuit_parser_module for core functionality.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Dict, Any

from biscuit_parser_module import BiscuitParser


def print_pretty_results(result: Dict[str, Any], output_format: str = "pretty") -> None:
    """Print results in either JSON or pretty format."""
    
    if output_format == "json":
        print(json.dumps(result, indent=2, default=str))
        return
    
    # Pretty print format
    print("=" * 60)
    print("BISCUIT TOKEN ANALYSIS")
    print("=" * 60)
    
    if "status" in result:
        print(f"Status: {result['status']}")
        
        if result["status"] == "verified":
            print("✅ Token verification: SUCCESS")
            print(f"Block count: {result.get('block_count', 'N/A')}")
            print(f"Token length: {result.get('token_length', 'N/A')} characters")
            
        elif result["status"] == "authorization_complete":
            auth_status = "✅ AUTHORIZED" if result["authorized"] else "❌ DENIED"
            print(f"Authorization: {auth_status}")
            print(f"User: {result['user_id']}")
            print(f"Resource: {result['resource']}")
            print(f"Operation: {result['operation']}")
            print(f"Auth code: {result['auth_code']}")
            
            if result["facts"]:
                print("\nToken Facts:")
                for fact_type, facts in result["facts"].items():
                    if facts:
                        print(f"  {fact_type}: {facts}")
                        
        elif result["status"] == "parsed_unverified":
            print("⚠️  Token parsed without verification")
            print(f"Block count: {result.get('block_count', 'N/A')}")
            print(f"Revocation IDs: {result.get('revocation_ids', 'N/A')}")
            
        elif "error" in result:
            print(f"❌ Error: {result['error']}")
    
    elif "token_analysis" in result:
        print("📊 COMPREHENSIVE ANALYSIS")
        print(f"Timestamp: {result['token_analysis']['timestamp']}")
        print(f"Token length: {result['token_analysis']['token_length']} characters")
        
        if "unverified_parse" in result:
            unverified = result["unverified_parse"]
            print(f"\nUnverified Parse: {unverified['status']}")
            if unverified["status"] == "parsed_unverified":
                print(f"  Block count: {unverified['block_count']}")
                print(f"  Revocation IDs: {unverified['revocation_ids']}")
        
        if "verification" in result:
            verification = result["verification"]
            print(f"\nVerification: {verification['status']}")
            if verification["status"] == "verified":
                print("  ✅ Cryptographic verification: SUCCESS")
            elif verification["status"] == "skipped":
                print("  ⚠️  Verification skipped (no public key)")
            elif "error" in verification:
                print(f"  ❌ Verification failed: {verification['error']}")
    
    elif "batch_analysis" in result:
        batch = result["batch_analysis"]
        print("📊 BATCH ANALYSIS")
        print(f"Timestamp: {batch['timestamp']}")
        print(f"Token count: {batch['token_count']}")
        print()
        
        for i, token_result in enumerate(batch['results']):
            print(f"--- Token {i + 1} ---")
            if "token_analysis" in token_result:
                analysis = token_result["token_analysis"]
                print(f"Length: {analysis['token_length']} characters")
                
                if "unverified_parse" in token_result:
                    unverified = token_result["unverified_parse"]
                    print(f"Parse: {unverified['status']}")
                    
                if "verification" in token_result:
                    verification = token_result["verification"]
                    print(f"Verification: {verification['status']}")
            print()
    
    print("=" * 60)


def handle_single_token_analysis(parser: BiscuitParser, args: argparse.Namespace) -> int:
    """Handle single token analysis operations."""
    
    if args.unverified_only:
        result = parser.parse_unverified(args.token)
    elif args.authorize:
        if not all([args.user, args.resource, args.operation]):
            print("Error: --user, --resource, and --operation are required for authorization")
            return 1
        result = parser.authorize_token(args.token, args.user, args.resource, args.operation)
    elif args.analyze:
        result = parser.analyze_token(args.token)
    else:
        # Default: verify and parse
        if args.public_key:
            result = parser.verify_and_parse(args.token)
        else:
            result = parser.parse_unverified(args.token)
    
    print_pretty_results(result, args.output)
    return 0


def handle_batch_analysis(parser: BiscuitParser, args: argparse.Namespace) -> int:
    """Handle batch token analysis."""
    
    try:
        with open(args.batch_file, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
        
        if not tokens:
            print("Error: No tokens found in batch file")
            return 1
        
        result = parser.batch_analyze(tokens)
        print_pretty_results(result, args.output)
        return 0
        
    except FileNotFoundError:
        print(f"Error: Batch file '{args.batch_file}' not found")
        return 1
    except Exception as e:
        print(f"Error reading batch file: {e}")
        return 1


def handle_quick_check(parser: BiscuitParser, args: argparse.Namespace) -> int:
    """Handle quick token validity check."""
    
    if not args.public_key:
        print("Error: --public-key is required for quick validity check")
        return 1
    
    is_valid = parser.is_token_valid(args.token)
    
    if args.output == "json":
        result = {
            "token_valid": is_valid,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        print(json.dumps(result, indent=2))
    else:
        status = "✅ VALID" if is_valid else "❌ INVALID"
        print(f"Token validity: {status}")
    
    return 0 if is_valid else 1


def main() -> int:
    """Main CLI entry point."""
    
    parser = argparse.ArgumentParser(
        description="Parse and authenticate Biscuit authorization tokens",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Parse token without verification
  %(prog)s TOKEN --unverified-only
  
  # Verify token with public key
  %(prog)s TOKEN --public-key PUBLIC_KEY_HEX
  
  # Authorize token for specific access
  %(prog)s TOKEN --public-key PUBLIC_KEY_HEX --authorize --user alice --resource /api/data --operation read
  
  # Comprehensive analysis
  %(prog)s TOKEN --public-key PUBLIC_KEY_HEX --analyze
  
  # Quick validity check
  %(prog)s TOKEN --public-key PUBLIC_KEY_HEX --quick-check
  
  # Batch analysis from file
  %(prog)s --batch-file tokens.txt --public-key PUBLIC_KEY_HEX
  
  # JSON output format
  %(prog)s TOKEN --analyze --output json
        """
    )
    
    # Positional argument for single token (optional for batch mode)
    parser.add_argument("token", nargs="?", help="Base64-encoded biscuit token to parse")
    
    # Authentication options
    parser.add_argument("--public-key", help="Public key in hex format for verification")
    
    # Authorization options
    parser.add_argument("--user", help="User ID for authorization check")
    parser.add_argument("--resource", help="Resource for authorization check")  
    parser.add_argument("--operation", help="Operation for authorization check")
    
    # Operation mode options
    parser.add_argument("--unverified-only", action="store_true",
                       help="Only parse without cryptographic verification")
    parser.add_argument("--authorize", action="store_true",
                       help="Perform full authorization check")
    parser.add_argument("--analyze", action="store_true",
                       help="Perform comprehensive token analysis")
    parser.add_argument("--quick-check", action="store_true",
                       help="Quick token validity check")
    
    # Batch processing
    parser.add_argument("--batch-file", help="File containing tokens (one per line) for batch analysis")
    
    # Output options
    parser.add_argument("--output", choices=["json", "pretty"], default="pretty",
                       help="Output format")
    
    # Verbose mode
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.batch_file and not args.token:
        parser.error("Either provide a token as positional argument or use --batch-file")
    
    if args.batch_file and args.token:
        parser.error("Cannot use both single token and batch file mode")
    
    # Initialize parser
    try:
        biscuit_parser = BiscuitParser(args.public_key)
    except Exception as e:
        print(f"Error initializing parser: {e}")
        return 1
    
    # Handle different operation modes
    try:
        if args.batch_file:
            return handle_batch_analysis(biscuit_parser, args)
        elif args.quick_check:
            return handle_quick_check(biscuit_parser, args)
        else:
            return handle_single_token_analysis(biscuit_parser, args)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        if args.verbose:
            import traceback
            traceback.print_exc()
        else:
            print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())