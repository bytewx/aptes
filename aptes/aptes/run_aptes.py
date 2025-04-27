#!/usr/bin/env python3
"""
APTES launcher script - run this from the project root
"""

import sys
import os

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add the current directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from aptes import main

if __name__ == "__main__":
    main()
