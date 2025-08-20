#!/usr/bin/env python3
"""
Test script for the new --csv-batch-size configuration option.
"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, 'src')

from flowlyzer.utils.config_manager import ConfigManager


def test_csv_batch_size_config():
    """Test the new --csv-batch-size configuration option."""
    print("Testing CSV Batch Size Configuration...")
    
    config_manager = ConfigManager()
    
    # Test with csv-batch-size argument
    test_args = [
        '--input', 'dummy.pcap',
        '--csv-batch-size', '25',
        '--batch-size', '30',
        '--workers', '4'
    ]
    
    try:
        args = config_manager.parse_arguments(test_args)
        processing_config = config_manager.get_processing_config()
        
        print(f"  ✓ CSV Batch Size: {processing_config.get('csv_batch_size', 'NOT_FOUND')}")
        print(f"  ✓ Processing Batch Size: {processing_config.get('batch_size', 'NOT_FOUND')}")
        print(f"  ✓ Workers: {processing_config.get('workers', 'NOT_FOUND')}")
        
        # Verify the values are correct
        assert processing_config.get('csv_batch_size') == 25, f"Expected 25, got {processing_config.get('csv_batch_size')}"
        assert processing_config.get('batch_size') == 30, f"Expected 30, got {processing_config.get('batch_size')}"
        
        print("  ✓ CSV batch size configuration working correctly!")
        return True
        
    except Exception as e:
        print(f"  ✗ Configuration test failed: {e}")
        return False


def test_default_values():
    """Test default values for CSV batch size."""
    print("\nTesting Default Values...")
    
    config_manager = ConfigManager()
    
    # Test with minimal arguments (should use defaults)
    test_args = ['--input', 'dummy.pcap']
    
    try:
        args = config_manager.parse_arguments(test_args)
        processing_config = config_manager.get_processing_config()
        
        csv_batch_size = processing_config.get('csv_batch_size', 'NOT_FOUND')
        batch_size = processing_config.get('batch_size', 'NOT_FOUND')
        
        print(f"  ✓ Default CSV Batch Size: {csv_batch_size}")
        print(f"  ✓ Default Processing Batch Size: {batch_size}")
        
        # Both should default to 30
        assert csv_batch_size == 30, f"Expected default 30, got {csv_batch_size}"
        assert batch_size == 30, f"Expected default 30, got {batch_size}"
        
        print("  ✓ Default values working correctly!")
        return True
        
    except Exception as e:
        print(f"  ✗ Default values test failed: {e}")
        return False


def test_independent_configuration():
    """Test that CSV batch size and processing batch size can be set independently."""
    print("\nTesting Independent Configuration...")
    
    config_manager = ConfigManager()
    
    # Test with different values for each
    test_args = [
        '--input', 'dummy.pcap',
        '--csv-batch-size', '15',  # Small CSV batches
        '--batch-size', '40'       # Larger processing batches
    ]
    
    try:
        args = config_manager.parse_arguments(test_args)
        processing_config = config_manager.get_processing_config()
        
        csv_batch_size = processing_config.get('csv_batch_size')
        batch_size = processing_config.get('batch_size')
        
        print(f"  ✓ CSV Batch Size: {csv_batch_size}")
        print(f"  ✓ Processing Batch Size: {batch_size}")
        
        # Verify they are independent
        assert csv_batch_size == 15, f"Expected 15, got {csv_batch_size}"
        assert batch_size == 40, f"Expected 40, got {batch_size}"
        assert csv_batch_size != batch_size, "Values should be different"
        
        print("  ✓ Independent configuration working correctly!")
        return True
        
    except Exception as e:
        print(f"  ✗ Independent configuration test failed: {e}")
        return False


def show_usage_examples():
    """Show usage examples with the new parameter."""
    print("\nUsage Examples with --csv-batch-size:")
    print("=" * 60)
    
    examples = [
        {
            'name': 'Real-time monitoring',
            'cmd': '--csv-batch-size 10 --batch-size 20',
            'desc': 'Frequent CSV updates for real-time analysis'
        },
        {
            'name': 'High performance',
            'cmd': '--csv-batch-size 60 --batch-size 40 --workers 8',
            'desc': 'Larger CSV batches for better I/O performance'
        },
        {
            'name': 'Memory constrained',
            'cmd': '--csv-batch-size 5 --batch-size 8 --workers 1',
            'desc': 'Very small batches for minimal memory usage'
        },
        {
            'name': 'Balanced (default)',
            'cmd': '--csv-batch-size 30 --batch-size 30',
            'desc': 'Default balanced approach'
        }
    ]
    
    for example in examples:
        print(f"\n{example['name']}:")
        print(f"  python -m src.flowlyzer.main -i Input/ --multi-folder {example['cmd']}")
        print(f"  # {example['desc']}")


def main():
    """Run all tests for CSV batch size configuration."""
    print("=" * 70)
    print("CSV Batch Size Configuration Test Suite")
    print("=" * 70)
    
    tests_passed = 0
    total_tests = 3
    
    # Run tests
    if test_csv_batch_size_config():
        tests_passed += 1
    
    if test_default_values():
        tests_passed += 1
    
    if test_independent_configuration():
        tests_passed += 1
    
    # Show results
    print("\n" + "=" * 70)
    print(f"Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("✓ All CSV batch size configuration tests passed!")
        show_usage_examples()
        print("\n" + "=" * 70)
        print("KEY BENEFITS of --csv-batch-size parameter:")
        print("• Independent control of processing vs. CSV writing")
        print("• Fine-tune memory usage vs. I/O performance")
        print("• Customize CSV update frequency (5-100 flows)")
        print("• Default: 30 flows per CSV batch (balanced approach)")
        print("=" * 70)
        return 0
    else:
        print(f"✗ {total_tests - tests_passed} tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())