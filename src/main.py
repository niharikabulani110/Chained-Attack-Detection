"""
Main module for WordPress Vulnerability Scanner.
This module coordinates the scanning process and handles the overall workflow.
"""

import argparse
import sys
import os
from typing import Dict, List, Optional, Generator
from datetime import datetime
import requests
from itertools import chain

from src.utils.file_utils import load_usernames, load_passwords
from src.scanners.user_enum import detect_user_enumeration
from src.scanners.brute_force import detect_bruteforce
from src.output.save_results import save_results, create_results
from src.utils.logger_config import setup_logger, logger
from src.utils.memory_monitor import MemoryMonitor

def validate_url(url: str) -> None:
    """
    Validate that the URL starts with http:// or https://.
    
    Args:
        url (str): The URL to validate
        
    Raises:
        ValueError: If the URL is invalid
    """
    logger.debug(f"Validating URL: {url}")
    if not url.startswith(('http://', 'https://')):
        raise ValueError("URL must start with http:// or https://")
    logger.debug("URL validation successful")

def validate_file(file_path: str, file_type: str) -> None:
    """
    Validate that a file exists and is readable.
    
    Args:
        file_path (str): Path to the file
        file_type (str): Type of file (for error message)
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        PermissionError: If the file isn't readable
    """
    logger.debug(f"Validating {file_type} file: {file_path}")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_type} file not found: {file_path}")
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"Cannot read {file_type} file: {file_path}")
    logger.debug(f"{file_type} file validation successful")

def main():
    """
    Main entry point for the WordPress Vulnerability Scanner.
    """
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(
            description='WordPress Vulnerability Scanner',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument('--url', required=True, help='Target WordPress URL')
        parser.add_argument('--userlist', required=True, help='Path to usernames file')
        parser.add_argument('--passlist', required=True, help='Path to passwords file')
        parser.add_argument('--output', help='Path to output file (optional)')
        parser.add_argument('--delay', type=int, default=1, help='Delay between requests in seconds')
        parser.add_argument('--max-attempts', type=int, default=5, help='Maximum number of brute force attempts')
        parser.add_argument('--chunk-size', type=int, default=1000, help='Number of items to process at once')
        parser.add_argument('--memory-limit', type=int, help='Maximum memory usage in MB')
        parser.add_argument('--max-workers', type=int, default=5, help='Maximum number of worker threads')
        parser.add_argument('--debug', action='store_true', help='Enable debug logging')
        parser.add_argument('--log-file', help='Path to log file (optional)')
        
        args = parser.parse_args()

        # Setup logger
        logger = setup_logger(debug=args.debug, log_file=args.log_file)
        logger.info("Starting WordPress vulnerability scanner")
        logger.debug(f"Command line arguments: {vars(args)}")

        # Initialize memory monitor
        memory_monitor = MemoryMonitor(
            memory_limit_mb=args.memory_limit,
            check_interval=100  # Check memory every 100 operations
        )

        # Validate inputs
        logger.info("Validating inputs...")
        validate_url(args.url)
        validate_file(args.userlist, "Usernames")
        validate_file(args.passlist, "Passwords")
        
        # Load usernames and passwords as chunked generators
        logger.info("Loading usernames and passwords...")
        username_chunks = load_usernames(args.userlist, chunk_size=args.chunk_size)
        password_chunks = load_passwords(args.passlist, chunk_size=args.chunk_size)
        
        # Check if generators are empty
        try:
            first_username_chunk = next(username_chunks)
            username_chunks = chain([first_username_chunk], username_chunks)  # Reconstruct generator
            memory_monitor.check_memory_usage()
        except StopIteration:
            logger.error("No usernames loaded. Exiting.")
            return
            
        try:
            first_password_chunk = next(password_chunks)
            password_chunks = chain([first_password_chunk], password_chunks)  # Reconstruct generator
            memory_monitor.check_memory_usage()
        except StopIteration:
            logger.error("No passwords loaded. Exiting.")
            return
        
        # Step 1: Detect User Enumeration
        logger.info("Checking for user enumeration vulnerability...")
        user_enum_detected, valid_usernames = detect_user_enumeration(
            args.url, 
            username_chunks, 
            delay=args.delay,
            max_workers=args.max_workers,
            memory_monitor=memory_monitor
        )
        
        # Step 2: If User Enumeration is successful, run Brute Force scan
        brute_force_detected, usernames_tested, credentials_found = False, [], []
        if user_enum_detected:
            logger.info("User enumeration detected. Attempting brute force with valid usernames...")
            # Convert valid_usernames list to a generator yielding chunks
            def valid_username_chunks():
                yield valid_usernames
            
            brute_force_detected, usernames_tested, credentials_found = detect_bruteforce(
                target_url=args.url,
                username_chunks=valid_username_chunks(),
                password_chunks=password_chunks,
                delay=args.delay,
                max_attempts=args.max_attempts,
                max_workers=args.max_workers,
                memory_monitor=memory_monitor
            )
        
        # Step 3: Format the results in the expected structure
        results = create_results(
            target_url=args.url,
            user_enum_detected=user_enum_detected,
            brute_force_detected=brute_force_detected,
            usernames_tested=usernames_tested,
            credentials_found=credentials_found
        )
        
        # Step 4: Save the results to a JSON file
        output_file = args.output or f"output/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_results(results, output_file)
        logger.info(f"Scan completed. Results saved to {output_file}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error occurred: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Invalid URL: {e}")
        sys.exit(1)
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"{e}")
        sys.exit(1)
    except MemoryError as e:
        logger.error(f"Memory limit exceeded: {e}")
        sys.exit(1)
    except argparse.ArgumentError as e:
        logger.error(f"Invalid argument: {e}")
        parser.print_help()
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 