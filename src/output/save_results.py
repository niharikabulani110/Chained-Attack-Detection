"""
Module for saving and formatting scan results.
"""

import json
import os
from typing import Dict, List, Any
from src.utils.logger_config import logger

def create_results(
    target_url: str,
    user_enum_detected: bool,
    brute_force_detected: bool,
    usernames_tested: List[str],
    credentials_found: List[Dict[str, str]]
) -> Dict[str, Any]:
    """
    Create a structured results dictionary in the expected format.
    
    Args:
        target_url (str): The target WordPress URL
        user_enum_detected (bool): Whether user enumeration was detected
        brute_force_detected (bool): Whether brute force vulnerability was detected
        usernames_tested (List[str]): List of usernames that were tested
        credentials_found (List[Dict]): List of dictionaries containing found credentials
        
    Returns:
        Dict[str, Any]: Results in the expected format
    """
    results = {
        "target": target_url,
        "vulnerabilities": []
    }
    
    # Add user enumeration results
    results["vulnerabilities"].append({
        "type": "User Enumeration",
        "detected": user_enum_detected,
        "vector": "/wp-login.php",
        "confidence": "medium"
    })
    
    # Add brute force results
    results["vulnerabilities"].append({
        "type": "Brute-force Login",
        "detected": brute_force_detected,
        "vector": "/wp-login.php",
        "usernames_tested": usernames_tested,
        "credentials_found": credentials_found,
        "confidence": "high" if credentials_found else "medium"
    })
    
    return results

def save_results(results: Dict[str, Any], output_file: str) -> None:
    """
    Save scan results to a JSON file.
    
    Args:
        results (Dict[str, Any]): Results dictionary to save
        output_file (str): Path to save the results file
        
    Raises:
        OSError: If there's an error creating the output directory or writing the file
        TypeError: If the results cannot be serialized to JSON
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Save results to file with proper encoding, truncating any existing content
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            f.truncate(0)  # Clear the file
            json.dump(results, f, indent=2, ensure_ascii=False)
            f.write('\n')  # Add newline at end of file
            
        logger.info(f"Results saved to {output_file}")
        
    except OSError as e:
        logger.error(f"Error saving results: {e}")
        raise
    except TypeError as e:
        logger.error(f"Error serializing results to JSON: {e}")
        raise

# Test block
if __name__ == "__main__":
    # Example usage
    test_results = create_results(
        target_url="http://example-wp.com",
        user_enum_detected=True,
        brute_force_detected=True,
        usernames_tested=["admin"],
        credentials_found=[{"username": "admin", "password": "admin123"}]
    )
    
    print(json.dumps(test_results, indent=2)) 