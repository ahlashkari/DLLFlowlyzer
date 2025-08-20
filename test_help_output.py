#!/usr/bin/env python3
"""
Simple test to verify the new --csv-batch-size parameter appears in help.
"""

import sys
import os
import subprocess

def test_help_output():
    """Test that --csv-batch-size appears in help output."""
    print("Testing --csv-batch-size parameter in help output...")
    
    try:
        # Run the main module with --help
        result = subprocess.run([
            sys.executable, '-m', 'src.flowlyzer.main', '--help'
        ], capture_output=True, text=True, cwd='.')
        
        help_output = result.stdout
        
        # Check if our new parameter is in the help
        if '--csv-batch-size' in help_output:
            print("  ✓ --csv-batch-size parameter found in help output")
            
            # Extract the help line
            for line in help_output.split('\n'):
                if '--csv-batch-size' in line:
                    print(f"  ✓ Help text: {line.strip()}")
                    break
            
            return True
        else:
            print("  ✗ --csv-batch-size parameter NOT found in help output")
            return False
            
    except Exception as e:
        print(f"  ✗ Error testing help output: {e}")
        return False


def show_relevant_parameters():
    """Show the relevant memory optimization parameters."""
    print("\nRelevant Memory Optimization Parameters:")
    print("=" * 50)
    print("--batch-size N          : Processing batch size (default: 30)")
    print("--csv-batch-size N      : CSV writing batch size (default: 30)")
    print("--disable-batching      : Disable batching entirely")
    print("--workers N             : Number of processing threads")
    print("--max-flows N           : Maximum concurrent flows")


def main():
    """Test the new CSV batch size parameter."""
    print("=" * 60)
    print("CSV Batch Size Parameter Verification")
    print("=" * 60)
    
    if test_help_output():
        print("\n✓ CSV batch size parameter successfully integrated!")
        show_relevant_parameters()
        
        print("\nExample Usage:")
        print("python -m src.flowlyzer.main -i Input/ --csv-batch-size 25 --batch-size 30")
        return 0
    else:
        print("\n✗ CSV batch size parameter not properly integrated")
        return 1


if __name__ == "__main__":
    sys.exit(main())