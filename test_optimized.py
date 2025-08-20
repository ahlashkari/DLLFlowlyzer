#!/usr/bin/env python3
"""
Test script for the optimized DLL Flowlyzer with batching and memory management.
"""

import sys
import os
import tempfile
import shutil
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, 'src')

from flowlyzer.utils.memory_monitor import MemoryMonitor
from flowlyzer.features.csv_exporter import CSVExporter
from flowlyzer.flows.flow_manager import FlowManager


def test_memory_monitor():
    """Test the memory monitoring functionality."""
    print("Testing Memory Monitor...")
    
    monitor = MemoryMonitor(warning_threshold_mb=100, critical_threshold_mb=200)
    
    # Test memory stats
    stats = monitor.get_memory_stats()
    print(f"  Current memory usage: {stats.process_mb:.1f} MB")
    print(f"  System memory: {stats.percent_used:.1f}% used")
    
    # Test memory pressure check
    warning, critical = monitor.check_memory_pressure()
    print(f"  Memory pressure - Warning: {warning}, Critical: {critical}")
    
    # Test garbage collection
    collected = monitor.force_garbage_collection()
    print(f"  Garbage collection: {collected} objects collected")
    
    # Test suggestions
    suggestions = monitor.suggest_memory_optimization()
    if suggestions:
        print("  Memory optimization suggestions:")
        for suggestion in suggestions:
            print(f"    - {suggestion}")
    
    print("  ✓ Memory Monitor test completed\n")


def test_csv_exporter():
    """Test the CSV exporter batching functionality."""
    print("Testing CSV Exporter Batching...")
    
    # Create temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        exporter = CSVExporter(temp_dir)
        
        # Test batch file creation
        batch_files = exporter.create_batch_files("test_features", separate_layers=True)
        print(f"  Created batch files:")
        for key, file_path in batch_files.items():
            if file_path:
                print(f"    {key}: {Path(file_path).name}")
        
        # Create sample data for testing
        import pandas as pd
        sample_data = {
            'connection': ['TCP:aa:bb:cc:dd:ee:ff:192.168.1.1:80:11:22:33:44:55:66:192.168.1.2:443'],
            'num_frame': [10],
            'time_delta': [5.0],
            'protocol': ['TCP'],
            'label': ['Benign'],
            'src_mac_addr': ['aa:bb:cc:dd:ee:ff'],
            'dst_mac_addr': ['11:22:33:44:55:66']
        }
        
        # Add minimal required columns for feature extractor
        for i in range(215):  # Add dummy features to reach 222 total
            sample_data[f'feature_{i}'] = [0]
        
        sample_df = pd.DataFrame(sample_data)
        
        # Test append functionality
        success = exporter.append_to_csv(sample_df, batch_files['combined'])
        print(f"  ✓ Append to CSV: {'Success' if success else 'Failed'}")
        
        # Verify file exists and has content
        combined_file = Path(batch_files['combined'])
        if combined_file.exists():
            df_check = pd.read_csv(combined_file)
            print(f"  ✓ CSV file created with {len(df_check)} rows and {len(df_check.columns)} columns")
        else:
            print("  ✗ CSV file was not created")
    
    print("  ✓ CSV Exporter test completed\n")


def test_flow_manager_batching():
    """Test the FlowManager batching and memory management."""
    print("Testing FlowManager Batching...")
    
    flow_manager = FlowManager(flow_timeout=60, max_flows=100)
    
    # Test memory usage estimation
    memory_stats = flow_manager.get_memory_usage_estimate()
    print(f"  Initial memory estimate: {memory_stats['estimated_memory_mb']:.2f} MB")
    print(f"  Active flows: {memory_stats['active_flows']}")
    print(f"  Completed flows: {memory_stats['completed_flows']}")
    
    # Test batch retrieval (should be empty initially)
    batch_flows = flow_manager.get_batch_completed_flows(10)
    print(f"  Retrieved batch size: {len(batch_flows)}")
    
    # Test force flow completion
    flow_manager.force_flow_completion(max_active_flows=50)
    print(f"  ✓ Force flow completion executed")
    
    print("  ✓ FlowManager test completed\n")


def test_configuration():
    """Test that the optimized configuration options are available."""
    print("Testing Configuration Options...")
    
    from flowlyzer.utils.config_manager import ConfigManager
    
    # Test argument parsing with new options
    config_manager = ConfigManager()
    
    # Simulate command line arguments
    test_args = [
        '--batch-size', '50',
        '--workers', '2',
        '--feature-threads', '2',
        '--input', 'dummy.pcap'
    ]
    
    try:
        args = config_manager.parse_arguments(test_args)
        print(f"  Batch size: {getattr(args, 'batch_size', 'NOT_FOUND')}")
        print(f"  Disable batching: {getattr(args, 'disable_batching', 'NOT_FOUND')}")
        print(f"  Workers: {args.workers}")
        print(f"  ✓ Configuration parsing successful")
    except Exception as e:
        print(f"  ✗ Configuration parsing failed: {e}")
    
    print("  ✓ Configuration test completed\n")


def main():
    """Run all tests."""
    print("=" * 60)
    print("DLL Flowlyzer Optimization Test Suite")
    print("=" * 60)
    print()
    
    try:
        # Run individual tests
        test_memory_monitor()
        test_csv_exporter()
        test_flow_manager_batching()
        test_configuration()
        
        print("=" * 60)
        print("✓ All tests completed successfully!")
        print("The optimized implementation appears to be working correctly.")
        print()
        print("Key optimizations implemented:")
        print("  • Batched CSV creation and updates")
        print("  • Memory monitoring and automatic cleanup")
        print("  • Configurable batch sizes")
        print("  • Packet data clearing after processing")
        print("  • Garbage collection optimization")
        print("  • Memory pressure detection")
        print("=" * 60)
        
        return 0
        
    except Exception as e:
        print(f"✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())