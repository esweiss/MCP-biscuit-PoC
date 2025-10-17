#!/usr/bin/env python3
"""
Simple utility to format Biscuit token facts for display.
Usage: python format_token_facts.py <token> <public_key>
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from biscuit_parser_module import BiscuitParser

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python format_token_facts.py <token> <public_key>", file=sys.stderr)
        sys.exit(1)
    
    token = sys.argv[1]
    public_key = sys.argv[2]
    
    parser = BiscuitParser(public_key)
    facts = parser.format_token_facts(token)
    print(facts)
