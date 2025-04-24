"""
Module for detecting WordPress user enumeration vulnerabilities.
"""

from src.utils.logger_config import logger
import requests
import time
from typing import List, Tuple

def detect_user_enumeration(url: str, usernames: List[str], delay: int = 1) -> Tuple[bool, List[str]]:
    """
    Detects if user enumeration is possible on the given WordPress login page.
    
    Args:
        url (str): Target WordPress URL (e.g., http://localhost:8080)
        usernames (List[str]): List of usernames to test
        delay (int): Optional delay (in seconds) between requests

    Returns:
        Tuple[bool, List[str]]: 
            - bool: Whether user enumeration was detected
            - List[str]: List of valid usernames found
    """
    detected = False
    valid_usernames = []
    login_url = url.rstrip("/") + "/wp-login.php"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; WP-EnumBot/1.0)"
    }

    for username in usernames:
        data = {
            "log": username,
            "pwd": "invalidPassword123!",
            "wp-submit": "Log In",
            "redirect_to": url,
            "testcookie": "1"
        }

        try:
            response = requests.post(login_url, data=data, headers=headers, timeout=5)
            
            # Check for different indicators of valid username
            if (
                "Invalid username" not in response.text or  # WordPress default message
                "The password you entered" in response.text or  # Alternative message
                "Lost your password" in response.text  # Password reset link
            ):
                detected = True
                valid_usernames.append(username)
                logger.warning(f"Valid username found: {username}")
            else:
                logger.debug(f"Invalid username: {username}")

            if delay:
                time.sleep(delay)

        except requests.RequestException as e:
            logger.error(f"Request failed for user '{username}': {e}")
            continue

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
    
    detected, valid_users = detect_user_enumeration(test_url, test_usernames, delay=1)
    print(f"User enumeration detected: {detected}")
    print(f"Valid usernames: {valid_users}") 