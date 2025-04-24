"""
Memory monitoring utilities for WordPress Vulnerability Scanner.
This module provides functionality to monitor and limit memory usage.
"""

import psutil
import logging
from typing import Optional
from src.utils.logger_config import logger

class MemoryMonitor:
    """
    A class to monitor and limit memory usage.
    """
    
    def __init__(self, memory_limit_mb: Optional[int] = None, check_interval: int = 1000):
        """
        Initialize the memory monitor.
        
        Args:
            memory_limit_mb (Optional[int]): Maximum memory usage in MB. If None, no limit is enforced.
            check_interval (int): Number of operations between memory checks (default: 1000)
        """
        self.memory_limit_mb = memory_limit_mb
        self.check_interval = check_interval
        self.operation_count = 0
        self.initial_memory = self._get_memory_usage()
        
        if memory_limit_mb is not None:
            logger.info(f"Memory limit set to {memory_limit_mb} MB")
    
    def _get_memory_usage(self) -> float:
        """
        Get current memory usage in MB.
        
        Returns:
            float: Current memory usage in MB
        """
        process = psutil.Process()
        return process.memory_info().rss / (1024 * 1024)  # Convert bytes to MB
    
    def check_memory_usage(self) -> None:
        """
        Check if memory usage exceeds the limit.
        
        Raises:
            MemoryError: If memory usage exceeds the limit
        """
        self.operation_count += 1
        
        if self.memory_limit_mb is None or self.operation_count % self.check_interval != 0:
            return
            
        current_memory = self._get_memory_usage()
        memory_increase = current_memory - self.initial_memory
        
        logger.debug(f"Memory usage: {current_memory:.2f} MB (increase: {memory_increase:.2f} MB)")
        
        if self.memory_limit_mb is not None and current_memory > self.memory_limit_mb:
            error_msg = f"Memory usage ({current_memory:.2f} MB) exceeded limit ({self.memory_limit_mb} MB)"
            logger.error(error_msg)
            raise MemoryError(error_msg)
    
    def reset(self) -> None:
        """
        Reset the operation count and initial memory usage.
        """
        self.operation_count = 0
        self.initial_memory = self._get_memory_usage()

# Test block
if __name__ == "__main__":
    # Example usage
    monitor = MemoryMonitor(memory_limit_mb=100)  # 100 MB limit
    
    try:
        # Simulate some operations
        for i in range(10000):
            # Create some memory usage
            _ = [i for i in range(10000)]
            monitor.check_memory_usage()
    except MemoryError as e:
        print(f"Memory limit exceeded: {e}") 