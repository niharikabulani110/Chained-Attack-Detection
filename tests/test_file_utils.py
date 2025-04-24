"""
Test suite for file utilities.
Tests file size checks and streaming functionality with large wordlists.
"""

import os
import tempfile
import pytest
from src.utils.file_utils import (
    check_file_size,
    stream_file,
    load_usernames,
    load_passwords,
    validate_file_path,
    create_directory
)

def test_file_size_check():
    """Test file size checking functionality."""
    # Create a temporary file with known size
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        # Write 1MB of data
        temp_file.write(b'0' * (1024 * 1024))
        temp_file_path = temp_file.name
    
    try:
        # Test with limit larger than file size
        check_file_size(temp_file_path, max_size_mb=2)
        
        # Test with limit smaller than file size
        with pytest.raises(ValueError):
            check_file_size(temp_file_path, max_size_mb=0.5)
            
        # Test with non-existent file
        with pytest.raises(FileNotFoundError):
            check_file_size("non_existent_file.txt")
            
    finally:
        # Clean up
        os.unlink(temp_file_path)

def test_stream_file():
    """Test file streaming functionality."""
    # Create a temporary file with test data
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        temp_file.write("line1\nline2\n\nline3\n")  # Include empty line
        temp_file_path = temp_file.name
    
    try:
        # Test streaming with size check
        lines = list(stream_file(temp_file_path, max_size_mb=1))
        assert lines == ["line1", "line2", "line3"]  # Empty line should be skipped
        
        # Test with large file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as large_file:
            # Write 2MB of data
            for i in range(2000):
                large_file.write(f"line{i}\n" * 100)
            large_file_path = large_file.name
            
        try:
            with pytest.raises(ValueError):
                list(stream_file(large_file_path, max_size_mb=1))
        finally:
            os.unlink(large_file_path)
            
    finally:
        os.unlink(temp_file_path)

def test_load_usernames():
    """Test username loading functionality."""
    # Create a temporary file with usernames
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        temp_file.write("admin\nuser1\n\nuser2\n")  # Include empty line
        temp_file_path = temp_file.name
    
    try:
        # Test loading usernames
        usernames = list(load_usernames(temp_file_path))
        assert usernames == ["admin", "user1", "user2"]  # Empty line should be skipped
        
        # Test with non-existent file
        usernames = list(load_usernames("non_existent_file.txt"))
        assert usernames == []  # Should return empty iterator
        
    finally:
        os.unlink(temp_file_path)

def test_load_passwords():
    """Test password loading functionality."""
    # Create a temporary file with passwords
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        temp_file.write("password1\npass123\n\nadmin123\n")  # Include empty line
        temp_file_path = temp_file.name
    
    try:
        # Test loading passwords
        passwords = list(load_passwords(temp_file_path))
        assert passwords == ["password1", "pass123", "admin123"]  # Empty line should be skipped
        
        # Test with non-existent file
        passwords = list(load_passwords("non_existent_file.txt"))
        assert passwords == []  # Should return empty iterator
        
    finally:
        os.unlink(temp_file_path)

def test_large_wordlist_handling():
    """Test handling of large wordlists."""
    # Create a large temporary file (1.5MB)
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as large_file:
        # Write 150,000 lines
        for i in range(150000):
            large_file.write(f"word{i}\n")
        large_file_path = large_file.name
    
    try:
        # Test with size limit
        with pytest.raises(ValueError):
            list(stream_file(large_file_path, max_size_mb=1))
            
        # Test with higher size limit
        words = list(stream_file(large_file_path, max_size_mb=2))
        assert len(words) == 150000  # All words should be read
        
        # Test memory usage
        import psutil
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Read the file again and check memory usage
        words = list(stream_file(large_file_path, max_size_mb=2))
        final_memory = process.memory_info().rss
        
        # Memory usage should not increase significantly
        memory_increase = (final_memory - initial_memory) / (1024 * 1024)  # Convert to MB
        assert memory_increase < 10  # Should use less than 10MB additional memory
        
    finally:
        os.unlink(large_file_path)

def test_validate_file_path():
    """Test file path validation."""
    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name
    
    try:
        # Test with valid file
        assert validate_file_path(temp_file_path) is True
        
        # Test with non-existent file
        with pytest.raises(FileNotFoundError):
            validate_file_path("non_existent_file.txt")
            
    finally:
        os.unlink(temp_file_path)

def test_create_directory():
    """Test directory creation."""
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Test creating directory that already exists
        assert create_directory(temp_dir) is True
        
        # Test creating new directory
        new_dir = os.path.join(temp_dir, "new_dir")
        assert create_directory(new_dir) is True
        assert os.path.exists(new_dir)
        
    finally:
        # Clean up
        import shutil
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    pytest.main([__file__]) 