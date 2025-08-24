#!/usr/bin/env python3
"""
Biscuit Token Generator

A utility for generating Biscuit authorization tokens with customizable facts,
rules, and checks. Biscuits are bearer tokens for authorization with 
attenuation and delegation capabilities.
"""

import argparse
from datetime import datetime, timedelta
from typing import List, Optional
import biscuit_auth as biscuit


class BiscuitGenerator:
    def __init__(self, private_key: Optional[str] = None):
        if private_key:
            self.private_key = biscuit.PrivateKey.from_hex(private_key)
        else:
            self.keypair = biscuit.KeyPair()
            self.private_key = self.keypair.private_key
    
    def create_basic_token(self, user_id: str, resource: str, operation: str) -> str:
        """Create a basic biscuit token with user, resource, and operation facts."""
        builder = biscuit.BiscuitBuilder()
        
        # Add basic facts
        builder.add_fact(biscuit.Fact(f'user("{user_id}")'))
        builder.add_fact(biscuit.Fact(f'resource("{resource}")'))
        builder.add_fact(biscuit.Fact(f'operation("{operation}")'))
        
        # Add a check to ensure the token is used with the correct user
        builder.add_check(biscuit.Check(f'check if user("{user_id}")'))
        
        token = builder.build(self.private_key)
        return token.to_base64()
    
    def create_time_limited_token(self, user_id: str, resource: str, 
                                operation: str, expires_in_hours: int = 24) -> str:
        """Create a time-limited biscuit token."""
        builder = biscuit.BiscuitBuilder()
        
        # Add basic facts
        builder.add_fact(biscuit.Fact(f'user("{user_id}")'))
        builder.add_fact(biscuit.Fact(f'resource("{resource}")'))
        builder.add_fact(biscuit.Fact(f'operation("{operation}")'))
        
        # Add expiration time
        expiry = datetime.now() + timedelta(hours=expires_in_hours)
        expiry_timestamp = int(expiry.timestamp())
        builder.add_fact(biscuit.Fact(f'expiry({expiry_timestamp})'))
        
        # Add checks
        builder.add_check(biscuit.Check(f'check if user("{user_id}")'))
        builder.add_check(biscuit.Check(f'check if time($time), expiry($expiry), $time <= $expiry'))
        
        token = builder.build(self.private_key)
        return token.to_base64()
    
    def create_scoped_token(self, user_id: str, resources: List[str], 
                          operations: List[str]) -> str:
        """Create a token with multiple resources and operations."""
        builder = biscuit.BiscuitBuilder()
        
        # Add user fact
        builder.add_fact(biscuit.Fact(f'user("{user_id}")'))
        
        # Add resource facts
        for resource in resources:
            builder.add_fact(biscuit.Fact(f'resource("{resource}")'))
        
        # Add operation facts
        for operation in operations:
            builder.add_fact(biscuit.Fact(f'operation("{operation}")'))
        
        # Add authorization rule
        builder.add_rule(biscuit.Rule('allow($user, $resource, $operation) <- '
                        f'user($user), resource($resource), operation($operation)'))
        
        # Add check to ensure proper authorization
        builder.add_check(biscuit.Check(f'check if allow("{user_id}", $resource, $operation)'))
        
        token = builder.build(self.private_key)
        return token.to_base64()
    
    def create_hierarchical_token(self, user_id: str, role: str, 
                                department: str, resource: str) -> str:
        """Create a token with hierarchical permissions."""
        builder = biscuit.BiscuitBuilder()
        
        # Add identity facts
        builder.add_fact(biscuit.Fact(f'user("{user_id}")'))
        builder.add_fact(biscuit.Fact(f'role("{role}")'))
        builder.add_fact(biscuit.Fact(f'department("{department}")'))
        builder.add_fact(biscuit.Fact(f'resource("{resource}")'))
        
        # Add role-based rules
        if role == "admin":
            builder.add_rule(biscuit.Rule(f'allow("{user_id}", "{resource}", "read") <- '
                           f'user("{user_id}"), role("admin"), resource("{resource}")'))
            builder.add_rule(biscuit.Rule(f'allow("{user_id}", "{resource}", "write") <- '
                           f'user("{user_id}"), role("admin"), resource("{resource}")'))
            builder.add_rule(biscuit.Rule(f'allow("{user_id}", "{resource}", "delete") <- '
                           f'user("{user_id}"), role("admin"), resource("{resource}")'))
        elif role == "manager":
            builder.add_rule(biscuit.Rule(f'allow("{user_id}", "{resource}", "read") <- '
                           f'user("{user_id}"), role("manager"), department("{department}"), resource("{resource}")'))
            builder.add_rule(biscuit.Rule(f'allow("{user_id}", "{resource}", "write") <- '
                           f'user("{user_id}"), role("manager"), department("{department}"), resource("{resource}")'))
        else:
            builder.add_rule(biscuit.Rule(f'allow("{user_id}", "{resource}", "read") <- '
                           f'user("{user_id}"), role("user"), resource("{resource}")'))
        
        # Add authorization check
        builder.add_check(biscuit.Check(f'check if allow("{user_id}", "{resource}", $operation)'))
        
        token = builder.build(self.private_key)
        return token.to_base64()
    
    def get_public_key(self) -> str:
        """Get the public key for token verification."""
        if hasattr(self, 'keypair'):
            return self.keypair.public_key.to_hex()
        else:
            # For keys loaded from hex, we need to extract the public key
            keypair = biscuit.KeyPair()
            return keypair.public_key.to_hex()
    
    def get_public_key_object(self):
        """Get the public key object for verification."""
        if hasattr(self, 'keypair'):
            return self.keypair.public_key
        else:
            keypair = biscuit.KeyPair()
            return keypair.public_key
    
    def create_custom_token(self, facts: List[str], rules: Optional[List[str]] = None, 
                          checks: Optional[List[str]] = None) -> str:
        """Create a biscuit token with custom facts, rules, and checks.
        
        Args:
            facts: List of fact strings (e.g., ['user("alice")', 'role("admin")'])
            rules: Optional list of rule strings (e.g., ['allow($u, $r, $o) <- user($u), resource($r), operation($o)'])
            checks: Optional list of check strings (e.g., ['check if user("alice")'])
            
        Returns:
            Base64-encoded biscuit token
        """
        builder = biscuit.BiscuitBuilder()
        
        # Add custom facts
        for fact_str in facts:
            builder.add_fact(biscuit.Fact(fact_str))
        
        # Add custom rules if provided
        if rules:
            for rule_str in rules:
                builder.add_rule(biscuit.Rule(rule_str))
        
        # Add custom checks if provided
        if checks:
            for check_str in checks:
                builder.add_check(biscuit.Check(check_str))
        
        token = builder.build(self.private_key)
        return token.to_base64()


def main():
    parser = argparse.ArgumentParser(description="Generate Biscuit authorization tokens")
    parser.add_argument("--user", required=True, help="User ID")
    parser.add_argument("--resource", required=True, help="Resource to access")
    parser.add_argument("--operation", default="read", help="Operation to perform")
    parser.add_argument("--type", choices=["basic", "time-limited", "scoped", "hierarchical", "custom"], 
                       default="basic", help="Type of token to generate")
    parser.add_argument("--expires-hours", type=int, default=24, 
                       help="Expiration time in hours (for time-limited tokens)")
    parser.add_argument("--resources", nargs="+", help="Multiple resources (for scoped tokens)")
    parser.add_argument("--operations", nargs="+", help="Multiple operations (for scoped tokens)")
    parser.add_argument("--role", help="User role (for hierarchical tokens)")
    parser.add_argument("--department", help="User department (for hierarchical tokens)")
    parser.add_argument("--private-key", help="Private key in hex format")
    parser.add_argument("--show-public-key", action="store_true", 
                       help="Show the public key for verification")
    parser.add_argument("--facts", nargs="+", help="Custom facts for custom tokens (e.g., 'user(\"alice\")' 'role(\"admin\")')")
    parser.add_argument("--rules", nargs="*", help="Custom rules for custom tokens (optional)")
    parser.add_argument("--checks", nargs="*", help="Custom checks for custom tokens (optional)")
    
    args = parser.parse_args()
    
    generator = BiscuitGenerator(args.private_key)
    
    if args.show_public_key:
        print(f"Public Key: {generator.get_public_key()}")
        print()
    
    if args.type == "basic":
        token = generator.create_basic_token(args.user, args.resource, args.operation)
        print(f"Basic Token: {token}")
    
    elif args.type == "time-limited":
        token = generator.create_time_limited_token(
            args.user, args.resource, args.operation, args.expires_hours)
        print(f"Time-Limited Token: {token}")
    
    elif args.type == "scoped":
        resources = args.resources or [args.resource]
        operations = args.operations or [args.operation]
        token = generator.create_scoped_token(args.user, resources, operations)
        print(f"Scoped Token: {token}")
    
    elif args.type == "hierarchical":
        if not args.role or not args.department:
            print("Error: --role and --department are required for hierarchical tokens")
            return 1
        token = generator.create_hierarchical_token(
            args.user, args.role, args.department, args.resource)
        print(f"Hierarchical Token: {token}")
    
    elif args.type == "custom":
        if not args.facts:
            print("Error: --facts is required for custom tokens")
            return 1
        token = generator.create_custom_token(
            args.facts, args.rules, args.checks)
        print(f"Custom Token: {token}")
    
    return 0


if __name__ == "__main__":
    exit(main())