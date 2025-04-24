"""
Module for detecting WordPress user enumeration vulnerabilities.
"""

from src.utils.logger_config import logger
import requests
import time
from typing import List, Tuple, Generator, Optional
from src.utils.memory_monitor import MemoryMonitor
from src.utils.parallel_utils import process_chunks_in_parallel

def check_username(url: str, username: str, headers: dict) -> Tuple[str, bool]:
    """
    Check if a username is valid.
    
    Args:
        url (str): Target WordPress URL
        username (str): Username to check
        headers (dict): HTTP headers to use
        
    Returns:
        Tuple[str, bool]: (username, is_valid)
    """
    data = {
        "log": username,
        "pwd": "invalidPassword123!",
        "wp-submit": "Log In",
        "redirect_to": url,
        "testcookie": "1"
    }
    
    try:
        response = requests.post(url, data=data, headers=headers, timeout=5)
        
        # More precise detection of invalid usernames
        invalid_indicators = [
            "Invalid username",  # Default message
            "Unknown username",  # Alternative message
            "not registered",    # Another variation
            "does not exist",    # Another variation
            "username is not registered"  # Another variation
        ]
        
        # Check if any invalid username indicators are present
        is_invalid = any(indicator.lower() in response.text.lower() 
                        for indicator in invalid_indicators)
        
        # Username is valid only if we don't see invalid indicators AND we see password-related messages
        password_indicators = [
            "The password you entered",
            "Lost your password",
            "Incorrect password",
            "password is incorrect"
        ]
        has_password_message = any(indicator.lower() in response.text.lower() 
                                 for indicator in password_indicators)
        
        # Username is valid only if:
        # 1. We don't see any invalid username messages
        # 2. We see password-related messages
        # 3. We don't see both types of messages (which would be ambiguous)
        is_valid = not is_invalid and has_password_message
        
        if is_valid:
            logger.warning(f"Valid username found: {username}")
        else:
            logger.debug(f"Invalid username: {username}")
            
        return username, is_valid
        
    except requests.RequestException as e:
        logger.error(f"Request failed for user '{username}': {e}")
        return username, False

def detect_user_enumeration(
    url: str, 
    username_chunks: Generator[List[str], None, None], 
    delay: int = 1,
    max_workers: int = 5,
    memory_monitor: Optional[MemoryMonitor] = None
) -> Tuple[bool, List[str]]:
    """
    Detects if user enumeration is possible on the given WordPress login page.
    
    Args:
        url (str): Target WordPress URL (e.g., http://localhost:8080)
        username_chunks (Generator[List[str], None, None]): Generator yielding chunks of usernames to test
        delay (int): Optional delay (in seconds) between requests
        max_workers (int): Maximum number of worker threads (default: 5)
        memory_monitor (Optional[MemoryMonitor]): Memory monitor instance for tracking memory usage

    Returns:
        Tuple[bool, List[str]]: 
            - bool: Whether user enumeration was detected
            - List[str]: List of valid usernames found
    """
    login_url = url.rstrip("/") + "/wp-login.php"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; WP-EnumBot/1.0)"
    }
    
    # Process username chunks in parallel
    def process_username(username: str) -> Tuple[str, bool]:
        result = check_username(login_url, username, headers)
        if delay:
            time.sleep(delay)
        return result
    
    results = process_chunks_in_parallel(
        chunk_generator=username_chunks,
        process_func=process_username,
        max_workers=max_workers,
        memory_monitor=memory_monitor
    )
    
    # Extract valid usernames from results
    valid_usernames = [username for username, is_valid in results if is_valid]
    detected = len(valid_usernames) > 0
    
    if detected:
        logger.warning(f"User enumeration vulnerability detected! Found {len(valid_usernames)} valid usernames")
    else:
        logger.info("No user enumeration vulnerability detected")

    return detected, valid_usernames

# Test block
if __name__ == "__main__":
    # Example usage
    test_url = "http://localhost:8080"  # Change this to the target WordPress URL
    test_usernames = ["admin", "notarealuser", "test"]
    
    # Convert test list to a generator yielding chunks
    def test_chunks():
        yield test_usernames
    
    detected, valid_users = detect_user_enumeration(
        test_url, 
        test_chunks(), 
        delay=1,
        max_workers=3
    )
    print(f"User enumeration detected: {detected}")
    print(f"Valid usernames: {valid_users}") 