"""
Command-line argument parser for WordPress Vulnerability Scanner.
This module handles the parsing and validation of command-line arguments.
"""

import argparse
import sys

def parse_arguments():
    """
    Parse and validate command-line arguments for the WordPress vulnerability scanner.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments with the following attributes:
            - url (str): Target WordPress URL
            - userlist (str): Path to file containing usernames
            - passlist (str): Path to file containing passwords
            - output (str): Path to save scan results
            - delay (int): Delay between requests in seconds
            - max_attempts (int): Maximum number of brute force attempts
            - debug (bool): Enable debug logging
            - log_file (str): Path to log file
    
    Raises:
        SystemExit: If required arguments are missing or invalid
    """
    # Initialize argument parser with description
    parser = argparse.ArgumentParser(
        description='WordPress Vulnerability Scanner - Detect common WordPress security issues'
    )
    
    # Required arguments
    parser.add_argument(
        '--url',
        required=True,
        help='Target WordPress URL (e.g., http://example.com)'
    )
    parser.add_argument(
        '--userlist',
        required=True,
        help='Path to file containing usernames to test'
    )
    parser.add_argument(
        '--passlist',
        required=True,
        help='Path to file containing passwords to test'
    )
    
    # Optional arguments
    parser.add_argument(
        '--output',
        help='Path to save scan results (default: results/scan_<timestamp>.json)'
    )
    parser.add_argument(
        '--delay',
        type=int,
        default=1,
        help='Delay between requests in seconds (default: 1)'
    )
    parser.add_argument(
        '--max-attempts',
        type=int,
        default=100,
        help='Maximum number of brute force attempts (default: 100)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--log-file',
        help='Path to log file (default: logs/scan_<timestamp>.log)'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate delay and max_attempts
    if args.delay < 0:
        parser.error("Delay must be a non-negative integer")
    if args.max_attempts < 1:
        parser.error("Maximum attempts must be a positive integer")
    
    return args

if __name__ == '__main__':
    # Test argument parsing
    try:
        args = parse_arguments()
        print("Arguments parsed successfully:")
        print(f"URL: {args.url}")
        print(f"Userlist: {args.userlist}")
        print(f"Passlist: {args.passlist}")
        print(f"Output: {args.output}")
        print(f"Delay: {args.delay}")
        print(f"Max Attempts: {args.max_attempts}")
        print(f"Debug: {args.debug}")
        print(f"Log File: {args.log_file}")
    except SystemExit as e:
        # Handle argument parsing errors
        sys.exit(e.code) 