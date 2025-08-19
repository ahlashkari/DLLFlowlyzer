#!/usr/bin/env python3
"""
Convenience script to run DLL Flowlyzer analysis.
"""

import sys
import subprocess
from pathlib import Path

def main():
    """Run DLL Flowlyzer with proper Python path setup."""
    
    # Add src to Python path
    src_path = Path(__file__).parent / "src"
    
    # Build command
    cmd = [
        sys.executable, "-m", "flowlyzer.main"
    ] + sys.argv[1:]
    
    # Set environment
    env = os.environ.copy() if 'os' in globals() else {}
    if 'PYTHONPATH' in env:
        env['PYTHONPATH'] = f"{src_path}:{env['PYTHONPATH']}"
    else:
        env['PYTHONPATH'] = str(src_path)
    
    # Run the analyzer
    try:
        result = subprocess.run(cmd, cwd=src_path, env=env)
        return result.returncode
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 1
    except Exception as e:
        print(f"Error running analyzer: {e}")
        return 1

if __name__ == "__main__":
    import os
    sys.exit(main())