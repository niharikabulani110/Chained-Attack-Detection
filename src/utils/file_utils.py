"""
File utility functions for WordPress Vulnerability Scanner.
This module handles file operations such as reading usernames and passwords from files.
"""

import os
import logging
from typing import Generator, Iterator, List
from src.utils.logger_config import logger

def check_file_size(file_path: str, max_size_mb: int = 100) -> None:
    """
    Check if a file size exceeds the maximum allowed size.
    
    Args:
        file_path (str): Path to the file to check
        max_size_mb (int): Maximum allowed file size in megabytes (default: 100MB)
        
    Raises:
        ValueError: If the file size exceeds the maximum allowed size
        FileNotFoundError: If the file doesn't exist
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
        
    file_size_bytes = os.path.getsize(file_path)
    file_size_mb = file_size_bytes / (1024 * 1024)  # Convert to MB
    
    if file_size_mb > max_size_mb:
        raise ValueError(
            f"File size ({file_size_mb:.2f}MB) exceeds maximum allowed size ({max_size_mb}MB). "
            f"Please use a smaller file or increase the size limit."
        )
    
    logger.debug(f"File size check passed: {file_path} ({file_size_mb:.2f}MB)")

def stream_file(file_path: str, max_size_mb: int = 100) -> Generator[str, None, None]:
    """
    Stream a file line by line, yielding non-empty lines.
    
    Args:
        file_path (str): Path to the file to stream
        max_size_mb (int): Maximum allowed file size in megabytes (default: 100MB)
        
    Yields:
        str: Each non-empty line from the file
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file size exceeds the maximum allowed size
    """
    if not os.path.exists(file_path):
        logger.warning(f"File not found: {file_path}")
        return
        
    check_file_size(file_path, max_size_mb)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:  # Only yield non-empty lines
                    yield line
    except IOError as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise

def load_usernames(path: str, max_size_mb: int = 100, chunk_size: int = 1000) -> Generator[List[str], None, None]:
    """
    Load usernames from a file, yielding chunks of usernames.
    
    Args:
        path (str): Path to the usernames file
        max_size_mb (int): Maximum allowed file size in megabytes (default: 100MB)
        chunk_size (int): Number of usernames to yield at once (default: 1000)
        
    Yields:
        List[str]: Chunks of usernames
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file size exceeds the maximum allowed size
    """
    check_file_size(path, max_size_mb)
    current_chunk = []
    
    for line in stream_file(path, max_size_mb):
        current_chunk.append(line.strip())
        if len(current_chunk) >= chunk_size:
            yield current_chunk
            current_chunk = []
    
    if current_chunk:  # Yield any remaining usernames
        yield current_chunk

def load_passwords(path: str, max_size_mb: int = 100, chunk_size: int = 1000) -> Generator[List[str], None, None]:
    """
    Load passwords from a file, yielding chunks of passwords.
    
    Args:
        path (str): Path to the passwords file
        max_size_mb (int): Maximum allowed file size in megabytes (default: 100MB)
        chunk_size (int): Number of passwords to yield at once (default: 1000)
        
    Yields:
        List[str]: Chunks of passwords
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        ValueError: If the file size exceeds the maximum allowed size
    """
    check_file_size(path, max_size_mb)
    current_chunk = []
    
    for line in stream_file(path, max_size_mb):
        current_chunk.append(line.strip())
        if len(current_chunk) >= chunk_size:
            yield current_chunk
            current_chunk = []
    
    if current_chunk:  # Yield any remaining passwords
        yield current_chunk

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

# Test block
if __name__ == "__main__":
    # Example usage
    try:
        # Test with a small file
        print("Testing with small file:")
        for i, username in enumerate(load_usernames("usernames.txt")):
            print(f"Username {i+1}: {username}")
            if i >= 4:  # Print first 5 usernames
                break
                
        # Test with a large file
        print("\nTesting with large file:")
        for i, password in enumerate(load_passwords("passwords.txt")):
            print(f"Password {i+1}: {password}")
            if i >= 4:  # Print first 5 passwords
                break
                
    except ValueError as e:
        print(f"Error: {e}")
    except FileNotFoundError as e:
        print(f"Error: {e}") 