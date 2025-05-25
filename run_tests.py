#!/usr/bin/env python3
"""
Script to run pytest with coverage reporting.

Usage:
    python run_tests.py              # Run all tests with coverage
    python run_tests.py --html       # Generate HTML coverage report only
    python run_tests.py --xml        # Generate XML coverage report only
    python run_tests.py --no-cov     # Run tests without coverage
"""

import sys
import subprocess
import os


def run_command(cmd):
    """Run a command and return success status."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    return result.returncode == 0


def main():
    """Main function to run pytest with various options."""
    # Change to the project directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Base pytest command
    cmd = ["python", "-m", "pytest"]
    
    # Parse simple arguments
    if "--no-cov" in sys.argv:
        # Run tests without coverage
        cmd.extend(["tests/", "-v"])
    elif "--html" in sys.argv:
        # Generate only HTML coverage report
        cmd.extend([
            "tests/",
            "--cov=app",
            "--cov-report=html:htmlcov",
            "--no-cov-report"
        ])
    elif "--xml" in sys.argv:
        # Generate only XML coverage report
        cmd.extend([
            "tests/",
            "--cov=app", 
            "--cov-report=xml:coverage.xml",
            "--no-cov-report"
        ])
    else:
        # Default: run with all coverage reports
        cmd.extend([
            "tests/",
            "--cov=app",
            "--cov-report=html:htmlcov",
            "--cov-report=xml:coverage.xml", 
            "--cov-report=term-missing",
            "-v"
        ])
    
    # Run the command
    success = run_command(cmd)
    
    if success:
        print("\n✅ Tests completed successfully!")
        if "--no-cov" not in sys.argv:
            print("📊 Coverage reports generated:")
            if os.path.exists("htmlcov/index.html"):
                print(f"  - HTML: file://{os.path.abspath('htmlcov/index.html')}")
            if os.path.exists("coverage.xml"):
                print(f"  - XML: {os.path.abspath('coverage.xml')}")
    else:
        print("\n❌ Tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()