#!/usr/bin/env python3
"""
Demonstration of the optimized DLL Flowlyzer with batching and memory management.

This script shows how to use the new optimization features:
- Batched CSV creation every N flows
- Memory monitoring and automatic cleanup
- Configurable batch sizes and thresholds
"""

import sys
import os
from pathlib import Path

def demonstrate_usage():
    """Demonstrate the optimized usage examples."""
    
    print("DLL Flowlyzer - Memory Optimized Processing")
    print("=" * 60)
    print()
    print("The following optimizations have been implemented:")
    print()
    
    print("1. BATCHED CSV PROCESSING:")
    print("   • Flows are processed in batches (default: 30 flows)")
    print("   • CSV files are created/updated after each batch")
    print("   • Memory is freed after each batch by clearing packet data")
    print()
    
    print("2. MEMORY MONITORING:")
    print("   • Real-time memory usage tracking")
    print("   • Automatic cleanup when memory thresholds are exceeded")
    print("   • Garbage collection optimization")
    print()
    
    print("3. CONFIGURABLE OPTIONS:")
    print("   • --batch-size N        : Set processing batch size (default: 30)")
    print("   • --csv-batch-size N    : Set CSV writing batch size (default: 30)")
    print("   • --disable-batching    : Disable batched processing")
    print("   • --workers N           : Reduce for lower memory usage")
    print("   • --max-flows N         : Limit concurrent flows")
    print()
    
    print("EXAMPLE USAGE:")
    print("=" * 60)
    print()
    
    print("# Standard optimized processing (recommended)")
    print("python -m src.flowlyzer.main -i Input/ --multi-folder")
    print()
    
    print("# Lower memory usage for large datasets")
    print("python -m src.flowlyzer.main -i Input/ --multi-folder \\")
    print("       --batch-size 20 --csv-batch-size 18 --workers 2 --max-flows 5000")
    print()
    
    print("# High performance with memory monitoring")
    print("python -m src.flowlyzer.main -i Input/ --multi-folder \\")
    print("       --batch-size 50 --csv-batch-size 45 --workers 6 --feature-threads 6")
    print()
    
    print("# Conservative memory usage with frequent CSV updates")
    print("python -m src.flowlyzer.main -i Input/ --multi-folder \\")
    print("       --batch-size 10 --csv-batch-size 8 --workers 1 --folder-threads 1")
    print()
    
    print("# Real-time processing with frequent updates")
    print("python -m src.flowlyzer.main -i Input/ --multi-folder \\")
    print("       --csv-batch-size 5 --batch-size 10 --workers 2")
    print()
    
    print("MEMORY BENEFITS:")
    print("=" * 60)
    print("• Reduced peak memory usage by processing flows in configurable batches")
    print("• Independent control of processing vs. CSV writing batch sizes")
    print("• Automatic cleanup of packet data after feature extraction")
    print("• Memory pressure detection with automatic flow completion")
    print("• Garbage collection optimization")
    print("• CSV files created incrementally with customizable frequency")
    print("• Fine-grained control over memory vs. I/O performance trade-offs")
    print()
    
    print("COMPATIBILITY:")
    print("=" * 60)
    print("• All existing commands continue to work unchanged")
    print("• Batching is enabled by default, use --disable-batching to turn off")
    print("• Memory monitoring works on all platforms with psutil")
    print("• CSV format and content remain identical")
    print()
    
    print("For detailed documentation, see the updated README.md and get-start.md files.")


if __name__ == "__main__":
    demonstrate_usage()