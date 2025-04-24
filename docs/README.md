# WordPress Vulnerability Scanner

A Python-based security tool for detecting common WordPress vulnerabilities, including user enumeration and weak authentication.

## Overview

This scanner helps identify security vulnerabilities in WordPress installations by:
- Detecting user enumeration vulnerabilities
- Testing for weak passwords through brute force attempts
- Providing detailed scan results and logging

The tool is designed for security professionals and system administrators to assess the security of WordPress installations.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/wp_vuln_detector.git
cd wp_vuln_detector
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python main.py --url http://example.com --userlist userlist.txt --passlist passlist.txt
```

Advanced usage with all options:
```bash
python main.py \
    --url http://example.com \
    --userlist userlist.txt \
    --passlist passlist.txt \
    --output results/scan.json \
    --delay 2 \
    --max-attempts 50 \
    --debug \
    --log-file logs/scan.log
```

### Command Line Arguments

- `--url`: Target WordPress URL (required)
- `--userlist`: Path to file containing usernames to test (required)
- `--passlist`: Path to file containing passwords to test (required)
- `--output`: Path to save scan results (optional)
- `--delay`: Delay between requests in seconds (default: 1)
- `--max-attempts`: Maximum number of brute force attempts (default: 100)
- `--debug`: Enable debug logging (optional)
- `--log-file`: Path to log file (optional)

## Project Components

### 1. Command Line Interface (`arg_parser.py`)
- Handles command-line argument parsing
- Validates input parameters
- Provides help messages and error handling

### 2. File Utilities (`file_utils.py`)
- Loads usernames and passwords from files
- Handles file reading errors
- Filters empty lines and whitespace

### 3. User Enumeration Detection (`user_enum.py`)
- Tests for WordPress user enumeration vulnerability
- Identifies valid usernames
- Implements rate limiting protection

### 4. Brute Force Detection (`brute_force.py`)
- Tests username/password combinations
- Detects successful logins
- Implements rate limiting and delay
- Handles network errors gracefully

### 5. Results Management (`save_results.py`)
- Saves scan results to JSON files
- Creates timestamp-based filenames
- Handles file writing errors

### 6. Logging System (`logger_config.py`)
- Configurable logging levels
- Console and file logging support
- Detailed debug information
- Error and warning tracking

## Output

The scanner generates two types of output:

1. **Console Output**:
   - Progress information
   - Found vulnerabilities
   - Error messages
   - Debug information (when enabled)

2. **Results File** (JSON format):
```json
{
    "target_url": "http://example.com",
    "scan_date": "2024-03-14 15:30:45",
    "user_enumeration": {
        "detected": true,
        "valid_usernames": ["admin", "test"]
    },
    "brute_force": {
        "attempted": true,
        "successful_logins": [
            {"username": "admin", "password": "admin123"}
        ]
    }
}
```

## Security Considerations

- Use responsibly and only on systems you have permission to test
- Respect rate limits and implement appropriate delays
- Do not use for malicious purposes
- Consider the legal implications of security testing

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 