"""
Rate limiting utilities for WordPress Vulnerability Scanner.
This module implements the leaky bucket algorithm for rate limiting.
"""

import time
import threading
from typing import Optional
from src.utils.logger_config import logger

class LeakyBucketRateLimiter:
    """
    Implements the leaky bucket algorithm for rate limiting.
    
    The leaky bucket algorithm:
    1. Has a bucket with a fixed capacity
    2. Tokens are added to the bucket at a fixed rate
    3. Each request consumes one token
    4. If the bucket is empty, requests must wait
    """
    
    def __init__(
        self,
        rate: float,  # tokens per second
        capacity: int,  # maximum tokens in bucket
        initial_tokens: Optional[int] = None
    ):
        """
        Initialize the rate limiter.
        
        Args:
            rate (float): Number of tokens added per second
            capacity (int): Maximum number of tokens the bucket can hold
            initial_tokens (Optional[int]): Initial number of tokens (defaults to capacity)
        """
        self.rate = rate
        self.capacity = capacity
        self.tokens = initial_tokens if initial_tokens is not None else capacity
        self.last_update = time.time()
        self.lock = threading.Lock()
        
    def _update_tokens(self) -> None:
        """
        Update the token count based on elapsed time.
        """
        now = time.time()
        time_passed = now - self.last_update
        new_tokens = time_passed * self.rate
        
        with self.lock:
            self.tokens = min(self.capacity, self.tokens + new_tokens)
            self.last_update = now
            
    def acquire(self, tokens: int = 1) -> float:
        """
        Acquire tokens from the bucket.
        
        Args:
            tokens (int): Number of tokens to acquire (default: 1)
            
        Returns:
            float: Time waited in seconds
        """
        if tokens > self.capacity:
            raise ValueError(f"Requested tokens ({tokens}) exceeds bucket capacity ({self.capacity})")
            
        wait_time = 0.0
        
        while True:
            with self.lock:
                self._update_tokens()
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return wait_time
                    
            # Wait for tokens to be available
            time.sleep(1.0 / self.rate)
            wait_time += 1.0 / self.rate
            
    def get_current_tokens(self) -> float:
        """
        Get the current number of tokens in the bucket.
        
        Returns:
            float: Current number of tokens
        """
        with self.lock:
            self._update_tokens()
            return self.tokens

# Test block
if __name__ == "__main__":
    # Example usage
    limiter = LeakyBucketRateLimiter(rate=5.0, capacity=10)  # 5 requests per second, max burst of 10
    
    def make_request(request_id: int) -> None:
        wait_time = limiter.acquire()
        print(f"Request {request_id} waited {wait_time:.2f}s, tokens: {limiter.get_current_tokens():.2f}")
    
    # Simulate some requests
    for i in range(15):
        make_request(i)
        time.sleep(0.1)  # Simulate some processing time 