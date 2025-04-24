"""
Test script to verify the output format and run multiple test scenarios.
"""

import json
import os
import sys
from typing import Dict, Any
import pytest
from src.main import main
from src.output.save_results import create_results

def verify_output_format(results: Dict[str, Any]) -> bool:
    """
    Verify that the output JSON contains all required fields and correct structure.
    
    Args:
        results (Dict[str, Any]): The results dictionary to verify
        
    Returns:
        bool: True if the format is correct, False otherwise
    """
    required_fields = {
        "target": str,
        "vulnerabilities": list
    }
    
    # Check top-level fields
    for field, field_type in required_fields.items():
        if field not in results:
            print(f"Missing required field: {field}")
            return False
        if not isinstance(results[field], field_type):
            print(f"Field {field} has wrong type: {type(results[field])}")
            return False
    
    # Check vulnerabilities array
    if len(results["vulnerabilities"]) != 2:
        print("Expected exactly 2 vulnerabilities in the array")
        return False
    
    # Check User Enumeration vulnerability
    user_enum = next((v for v in results["vulnerabilities"] if v["type"] == "User Enumeration"), None)
    if not user_enum:
        print("Missing User Enumeration vulnerability")
        return False
    
    required_user_enum_fields = {
        "type": str,
        "detected": bool,
        "vector": str,
        "confidence": str
    }
    
    for field, field_type in required_user_enum_fields.items():
        if field not in user_enum:
            print(f"Missing required field in User Enumeration: {field}")
            return False
        if not isinstance(user_enum[field], field_type):
            print(f"Field {field} in User Enumeration has wrong type: {type(user_enum[field])}")
            return False
    
    # Check Brute-force Login vulnerability
    brute_force = next((v for v in results["vulnerabilities"] if v["type"] == "Brute-force Login"), None)
    if not brute_force:
        print("Missing Brute-force Login vulnerability")
        return False
    
    required_brute_force_fields = {
        "type": str,
        "detected": bool,
        "vector": str,
        "usernames_tested": list,
        "credentials_found": list,
        "confidence": str
    }
    
    for field, field_type in required_brute_force_fields.items():
        if field not in brute_force:
            print(f"Missing required field in Brute-force Login: {field}")
            return False
        if not isinstance(brute_force[field], field_type):
            print(f"Field {field} in Brute-force Login has wrong type: {type(brute_force[field])}")
            return False
    
    return True

def test_output_format():
    """Test the output format with various scenarios."""
    test_cases = [
        {
            "name": "No vulnerabilities detected",
            "target_url": "http://example-wp.com",
            "user_enum_detected": False,
            "brute_force_detected": False,
            "usernames_tested": [],
            "credentials_found": []
        },
        {
            "name": "User enumeration detected",
            "target_url": "http://example-wp.com",
            "user_enum_detected": True,
            "brute_force_detected": False,
            "usernames_tested": ["admin"],
            "credentials_found": []
        },
        {
            "name": "Both vulnerabilities detected",
            "target_url": "http://example-wp.com",
            "user_enum_detected": True,
            "brute_force_detected": True,
            "usernames_tested": ["admin"],
            "credentials_found": [{"username": "admin", "password": "admin123"}]
        }
    ]
    
    for case in test_cases:
        print(f"\nTesting scenario: {case['name']}")
        results = create_results(
            target_url=case["target_url"],
            user_enum_detected=case["user_enum_detected"],
            brute_force_detected=case["brute_force_detected"],
            usernames_tested=case["usernames_tested"],
            credentials_found=case["credentials_found"]
        )
        
        assert verify_output_format(results), f"Output format verification failed for scenario: {case['name']}"
        print(f"Output format verification passed for scenario: {case['name']}")
        
        # Print the results for manual inspection
        print("\nResults:")
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    test_output_format() 