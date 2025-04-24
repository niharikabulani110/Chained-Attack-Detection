"""
File utility functions for WordPress Vulnerability Scanner.
This module handles file operations such as reading usernames and passwords from files.
"""

import os
import logging

def read_file(file_path):
    """
    Read and process a file containing usernames or passwords.
    
    Args:
        file_path (str): Path to the file to read
        
    Returns:
        list: List of non-empty lines from the file, stripped of whitespace
        
    Raises:
        FileNotFoundError: If the file does not exist
        IOError: If there is an error reading the file
    """
    # Check if file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    try:
        # Read file and process lines
        with open(file_path, 'r', encoding='utf-8') as file:
            # Filter out empty lines and strip whitespace
            lines = [line.strip() for line in file if line.strip()]
            
            if not lines:
                logging.warning(f"File {file_path} is empty")
            
            return lines
    except IOError as e:
        logging.error(f"Error reading file {file_path}: {str(e)}")
        raise

def validate_file_path(file_path):
    """
    Validate that a file path exists and is readable.
    
    Args:
        file_path (str): Path to validate
        
    Returns:
        bool: True if the file exists and is readable
        
    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If the file is not readable
    """
    # Check if file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Check if file is readable
    if not os.access(file_path, os.R_OK):
        raise PermissionError(f"File is not readable: {file_path}")
    
    return True

def create_directory(directory_path):
    """
    Create a directory if it doesn't exist.
    
    Args:
        directory_path (str): Path to the directory to create
        
    Returns:
        bool: True if directory was created or already exists
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(directory_path, exist_ok=True)
        return True
    except OSError as e:
        logging.error(f"Error creating directory {directory_path}: {str(e)}")
        return False

def load_usernames(path):
    """
    Loads usernames from a given file path.
    Each line in the file should contain one username.
    Returns a list of usernames.
    """
    try:
        with open(path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Usernames file not found: {path}")
        return []

def load_passwords(path):
    """
    Loads passwords from a given file path.
    Each line in the file should contain one password.
    Returns a list of passwords.
    """
    try:
        with open(path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] Passwords file not found: {path}")
        return []

# Test block
if __name__ == "__main__":
    usernames = load_usernames('usernames.txt')
    passwords = load_passwords('passwords.txt')
    print("Loaded usernames:", usernames)
    print("Loaded passwords:", passwords) 