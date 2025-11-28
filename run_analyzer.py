

import sys
import subprocess
from pathlib import Path

def main():

    src_path = Path(__file__).parent / "src"

    cmd = [
        sys.executable, "-m", "flowlyzer.main"
    ] + sys.argv[1:]

    env = os.environ.copy() if 'os' in globals() else {}
    if 'PYTHONPATH' in env:
        env['PYTHONPATH'] = f"{src_path}:{env['PYTHONPATH']}"
    else:
        env['PYTHONPATH'] = str(src_path)

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