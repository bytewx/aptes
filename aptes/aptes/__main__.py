#!/usr/bin/env python3
"""
Main entry point for APTES when run as a module
"""

import os
import sys

# Add the parent directory to sys.path to enable imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now use absolute imports
from aptes.aptes import main

if __name__ == "__main__":
    main()
