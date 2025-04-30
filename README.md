# WordPress Vulnerability Scanner

This script detects two types of vulnerabilities on WordPress sites:
1. **User Enumeration** - Detects if a WordPress site reveals valid usernames through error messages.
2. **Brute-Force Login** - Tries to brute-force login by testing common usernames and passwords.

### Features:
- User Enumeration detection by testing invalid logins with a list of usernames.
- Brute-Force Login detection by attempting common username-password combinations.
- Results are printed in JSON format for easy integration with other tools.

### Requirements:
- Python 3.x
- `requests` library (can be installed using `pip`)

### Installation:
1. Clone the repository or download the `scanner.py` script and `usernames.txt`, `passwords.txt` files.
2. Install the required Python dependencies:
    ```bash
    pip install requests
    ```

### Files:
- **`scanner.py`**: The main Python script for running the scan.
- **`usernames.txt`**: A file containing the list of usernames to test for user enumeration and brute-force login.
- **`passwords.txt`**: A file containing the list of passwords to test for brute-force login attempts.

### Usage:
1. Prepare your `usernames.txt` and `passwords.txt` files. Each file should have one username or password per line.
2. Open your terminal and navigate to the folder where `scanner.py` is located.
3. Run the script using the following command:
    ```bash
    python scanner.py <URL> --usernames <usernames_file> --passwords <passwords_file>
    ```
    Replace `<URL>` with the WordPress site's URL you want to scan. For example:
    ```bash
    python scanner.py http://localhost/wordpress --usernames usernames.txt --passwords passwords.txt
    ```

### Example:
```bash
python scanner.py http://example.com/wordpress --usernames usernames.txt --passwords passwords.txt
