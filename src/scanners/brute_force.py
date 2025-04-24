"""
Module for detecting WordPress brute-force login vulnerabilities.
"""

import requests
from time import sleep
from typing import List, Dict, Optional, Tuple, Generator
import re
from src.utils.logger_config import logger
from src.utils.memory_monitor import MemoryMonitor
from src.utils.parallel_utils import process_chunks_in_parallel
from src.utils.rate_limiter import LeakyBucketRateLimiter

def check_credentials(
    login_url: str,
    username: str,
    password: str,
    headers: dict,
    success_indicators: List[str],
    rate_limit_indicators: List[str],
    rate_limiter: Optional[LeakyBucketRateLimiter] = None
) -> Tuple[str, str, bool, bool]:
    """
    Check if credentials are valid.
    
    Args:
        login_url (str): WordPress login URL
        username (str): Username to test
        password (str): Password to test
        headers (dict): HTTP headers to use
        success_indicators (List[str]): List of regex patterns indicating successful login
        rate_limit_indicators (List[str]): List of regex patterns indicating rate limiting
        rate_limiter (Optional[LeakyBucketRateLimiter]): Rate limiter instance
        
    Returns:
        Tuple[str, str, bool, bool]: (username, password, is_valid, is_rate_limited)
    """
    if rate_limiter:
        wait_time = rate_limiter.acquire()
        if wait_time > 0:
            logger.debug(f"Rate limited: waited {wait_time:.2f}s")
    
    data = {
        'log': username,
        'pwd': password,
        'wp-submit': 'Log In',
        'redirect_to': f'{login_url}/wp-admin/',
        'testcookie': 1
    }
    
    try:
        response = requests.post(login_url, data=data, headers=headers, timeout=5)
        
        # Check for rate limiting
        is_rate_limited = (
            response.status_code in [429, 403] or 
            any(re.search(pattern, response.text.lower()) for pattern in rate_limit_indicators)
        )
        
        if is_rate_limited:
            return username, password, False, True
            
        # Check for successful login
        is_valid = (
            any(re.search(pattern, response.url.lower()) for pattern in success_indicators) or
            any(re.search(pattern, response.text.lower()) for pattern in success_indicators)
        )
        
        if is_valid:
            logger.warning(f"Valid credentials found: {username}:{password}")
        else:
            logger.debug(f"Invalid credentials: {username}:{password}")
            
        return username, password, is_valid, False
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error for {username}:{password}: {e}")
        return username, password, False, False

def detect_bruteforce(
    target_url: str,
    username_chunks: Generator[List[str], None, None],
    password_chunks: Generator[List[str], None, None],
    delay: int = 1,
    max_attempts: Optional[int] = None,
    max_workers: int = 5,
    memory_monitor: Optional[MemoryMonitor] = None,
    rate_limit: Optional[float] = None,  # requests per second
    burst_capacity: Optional[int] = None  # maximum burst size
) -> Tuple[bool, List[str], List[Dict[str, str]]]:
    """
    Detects WordPress login vulnerabilities by attempting brute force login attempts.
    
    Args:
        target_url (str): Target WordPress URL
        username_chunks (Generator[List[str], None, None]): Generator yielding chunks of usernames to test
        password_chunks (Generator[List[str], None, None]): Generator yielding chunks of passwords to test
        delay (int): Delay in seconds between attempts (default: 1)
        max_attempts (Optional[int]): Maximum number of attempts before stopping (None for unlimited)
        max_workers (int): Maximum number of worker threads (default: 5)
        memory_monitor (Optional[MemoryMonitor]): Memory monitor instance for tracking memory usage
        rate_limit (Optional[float]): Maximum requests per second (None for no rate limiting)
        burst_capacity (Optional[int]): Maximum burst size for rate limiting (None for default)
    
    Returns:
        Tuple[bool, List[str], List[Dict[str, str]]]:
            - bool: Whether brute-force vulnerability was detected
            - List[str]: List of usernames that were tested
            - List[Dict[str, str]]: List of dictionaries containing successful login credentials
    """
    detected = False
    usernames_tested = []
    credentials_found = []
    attempt_count = 0
    rate_limited = False
    
    login_url = f"{target_url.rstrip('/')}/wp-login.php"
    
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
    
    # Initialize rate limiter if specified
    rate_limiter = None
    if rate_limit is not None:
        capacity = burst_capacity if burst_capacity is not None else max(10, int(rate_limit * 2))
        rate_limiter = LeakyBucketRateLimiter(rate=rate_limit, capacity=capacity)
        logger.info(f"Rate limiting enabled: {rate_limit} requests/second, burst capacity: {capacity}")
    
    for username_chunk in username_chunks:
        if rate_limited:
            logger.warning("Rate limiting detected. Stopping brute force attempts.")
            break
            
        if memory_monitor:
            memory_monitor.check_memory_usage()
            
        for username in username_chunk:
            if username not in usernames_tested:
                usernames_tested.append(username)
            
            # Process password chunks in parallel
            def process_password(password: str) -> Tuple[str, str, bool, bool]:
                nonlocal attempt_count
                
                if max_attempts is not None and attempt_count >= max_attempts:
                    return username, password, False, False
                    
                result = check_credentials(
                    login_url=login_url,
                    username=username,
                    password=password,
                    headers=headers,
                    success_indicators=success_indicators,
                    rate_limit_indicators=rate_limit_indicators,
                    rate_limiter=rate_limiter
                )
                
                attempt_count += 1
                
                if delay and not rate_limiter:  # Only use fixed delay if not using rate limiter
                    sleep(delay)
                    
                return result
            
            results = process_chunks_in_parallel(
                chunk_generator=password_chunks,
                process_func=process_password,
                max_workers=max_workers,
                memory_monitor=memory_monitor
            )
            
            # Process results
            for _, password, is_valid, is_rate_limited in results:
                if is_valid:
                    detected = True
                    credentials_found.append({"username": username, "password": password})
                
                if is_rate_limited:
                    rate_limited = True
                    logger.warning("Rate limiting detected!")
                    logger.info("Consider increasing the delay parameter or using rate limiting")
                    break
            
            if rate_limited:
                break
            
            if max_attempts is not None and attempt_count >= max_attempts:
                logger.info(f"Reached maximum attempts ({max_attempts}). Stopping.")
                return detected, usernames_tested, credentials_found
    
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
    
    # Convert test lists to generators yielding chunks
    def test_username_chunks():
        yield test_usernames
        
    def test_password_chunks():
        yield test_passwords
    
    logger.info("Starting brute force test...")
    detected, tested_users, found_creds = detect_bruteforce(
        target_url=url,
        username_chunks=test_username_chunks(),
        password_chunks=test_password_chunks(),
        delay=1,
        max_attempts=10,
        max_workers=3,
        rate_limit=5.0,  # 5 requests per second
        burst_capacity=10  # Allow bursts of up to 10 requests
    )
    
    print(f"Brute force detected: {detected}")
    print(f"Usernames tested: {tested_users}")
    print(f"Credentials found: {found_creds}") 