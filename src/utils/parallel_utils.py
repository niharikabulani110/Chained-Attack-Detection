"""
Parallel processing utilities for WordPress Vulnerability Scanner.
This module provides functionality for parallel processing of tasks.
"""

import concurrent.futures
from typing import List, Callable, Any, Generator, TypeVar, Tuple, Optional
from src.utils.logger_config import logger
from src.utils.memory_monitor import MemoryMonitor

T = TypeVar('T')

def process_in_parallel(
    items: List[T],
    process_func: Callable[[T], Any],
    max_workers: int = 5,
    memory_monitor: Optional[MemoryMonitor] = None
) -> List[Any]:
    """
    Process a list of items in parallel using ThreadPoolExecutor.
    
    Args:
        items (List[T]): List of items to process
        process_func (Callable[[T], Any]): Function to process each item
        max_workers (int): Maximum number of worker threads (default: 5)
        memory_monitor (Optional[MemoryMonitor]): Memory monitor instance
        
    Returns:
        List[Any]: Results from processing each item
    """
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_item = {executor.submit(process_func, item): item for item in items}
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_item):
            item = future_to_item[future]
            try:
                result = future.result()
                results.append(result)
                
                # Check memory usage after each batch of results
                if memory_monitor:
                    memory_monitor.check_memory_usage()
                    
            except Exception as e:
                logger.error(f"Error processing item {item}: {e}")
    
    return results

def process_chunks_in_parallel(
    chunk_generator: Generator[List[T], None, None],
    process_func: Callable[[T], Any],
    max_workers: int = 5,
    memory_monitor: Optional[MemoryMonitor] = None
) -> List[Any]:
    """
    Process chunks of items in parallel using ThreadPoolExecutor.
    
    Args:
        chunk_generator (Generator[List[T], None, None]): Generator yielding chunks of items
        process_func (Callable[[T], Any]): Function to process each item
        max_workers (int): Maximum number of worker threads (default: 5)
        memory_monitor (Optional[MemoryMonitor]): Memory monitor instance
        
    Returns:
        List[Any]: Results from processing all items
    """
    all_results = []
    
    for chunk in chunk_generator:
        if memory_monitor:
            memory_monitor.check_memory_usage()
            
        chunk_results = process_in_parallel(
            items=chunk,
            process_func=process_func,
            max_workers=max_workers,
            memory_monitor=memory_monitor
        )
        all_results.extend(chunk_results)
    
    return all_results

# Test block
if __name__ == "__main__":
    # Example usage
    def square(x: int) -> int:
        return x * x
    
    # Test parallel processing of a list
    numbers = list(range(10))
    results = process_in_parallel(numbers, square)
    print(f"Parallel results: {results}")
    
    # Test parallel processing of chunks
    def number_chunks():
        yield [1, 2, 3]
        yield [4, 5, 6]
        yield [7, 8, 9]
    
    chunk_results = process_chunks_in_parallel(number_chunks(), square)
    print(f"Chunk results: {chunk_results}") 