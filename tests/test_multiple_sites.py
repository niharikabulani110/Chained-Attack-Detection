"""
Test script to run scans against multiple WordPress sites.
"""

import json
import os
import sys
from typing import Dict, Any, List
import requests
from src.main import main
from src.output.save_results import create_results, save_results
from src.utils.logger_config import logger

def test_wordpress_site(url: str, output_file: str) -> bool:
    """
    Test a WordPress site for vulnerabilities.
    
    Args:
        url (str): The WordPress site URL to test
        output_file (str): Path to save the results
        
    Returns:
        bool: True if the test completed successfully, False otherwise
    """
    try:
        # Verify the site is accessible
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            logger.error(f"Site {url} returned status code {response.status_code}")
            return False
        
        # Check if it's a WordPress site
        if "wp-content" not in response.text and "wp-includes" not in response.text:
            logger.error(f"Site {url} does not appear to be a WordPress site")
            return False
        
        # Run the scan
        logger.info(f"Starting scan for {url}")
        main([
            "--url", url,
            "--userlist", "data/usernames.txt",
            "--passlist", "data/passwords.txt",
            "--output", output_file,
            "--debug"
        ])
        
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error testing site {url}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error testing site {url}: {e}")
        return False

def test_multiple_sites():
    """Test multiple WordPress sites."""
    test_sites = [
        {
            "url": "http://example-wp.com",
            "description": "Example WordPress site (should fail to connect)"
        },
        {
            "url": "https://wordpress.org",
            "description": "Official WordPress site (should be secure)"
        },
        {
            "url": "https://demo.wp-api.org",
            "description": "WordPress API demo site"
        }
    ]
    
    results_dir = "output/multiple_sites"
    os.makedirs(results_dir, exist_ok=True)
    
    for site in test_sites:
        print(f"\nTesting site: {site['url']} ({site['description']})")
        output_file = os.path.join(results_dir, f"results_{site['url'].replace('://', '_').replace('/', '_')}.json")
        
        success = test_wordpress_site(site["url"], output_file)
        if success:
            print(f"Scan completed successfully. Results saved to {output_file}")
        else:
            print(f"Scan failed for {site['url']}")

if __name__ == "__main__":
    test_multiple_sites() 