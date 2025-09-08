#!/usr/bin/env python3
"""
Setup script for APTES package
"""

import os
import sys
import subprocess
from setuptools import setup, find_packages, Command

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# List of required system tools
SYSTEM_TOOLS = {
    "nmap": "Network scanning utility",
    "dig": "DNS lookup utility",
    "nbtscan": "NetBIOS scanning utility",
    "sqlmap": "SQL injection testing tool",
    "openssl": "SSL/TLS toolkit",
    "subfinder": "Subdomain discovery tool",
    "dnsrecon": "DNS enumeration script",
    "commix": "Command injection exploitation tool",
    "hydra": "Login cracker",
    "nikto": "Vulnerability scanner"
}

class InstallSystemDepsCommand(Command):
    """Custom command to install system dependencies."""
    description = 'Install required system tools'
    user_options = []
    
    def initialize_options(self):
        pass
    
    def finalize_options(self):
        pass
    
    def run(self):
        print("Checking for required system tools...")
        missing_tools = []
        
        for tool, description in SYSTEM_TOOLS.items():
            try:
                subprocess.check_call(['which', tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(f"✓ {tool} found")
            except subprocess.CalledProcessError:
                missing_tools.append(tool)
                print(f"✗ {tool} not found - {description}")
        
        if missing_tools:
            print("\nMissing tools. Install them with:\n")
            print("Ubuntu/Debian:")
            print(f"sudo apt update && sudo apt install -y {' '.join(missing_tools)}")
            print("\nFedora/RHEL/CentOS:")
            print(f"sudo dnf install -y {' '.join(missing_tools)}")
            print("\nArch Linux:")
            print(f"sudo pacman -S {' '.join(missing_tools)}")
            
            print("\nNote: Some tools may require additional repositories or manual installation.")
            print("For detailed installation instructions, visit: https://github.com/byteshell/aptes/wiki/installation")

setup(
    name="aptes",
    version="1.1.0",  # Updated version
    author="APTES Team",
    author_email="info@aptes.example.com",
    description="Advanced Penetration Testing and Exploitation Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/byteshell/aptes",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.28.0",
        "urllib3>=1.26.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
    ],
    extras_require={
        "reports": ["openpyxl>=3.1.0"],
        "ssh": ["paramiko>=3.0.0"],
        "webcrawl": [
            "scrapy>=2.11.0", 
            "pyopenssl>=23.0.0",
            "twisted>=22.10.0",
            "cryptography>=41.0.0",
        ],
        "full": [
            "openpyxl>=3.1.0",
            "scrapy>=2.11.0",
            "paramiko>=3.0.0",
            "pyopenssl>=23.0.0",
            "twisted>=22.10.0",
            "cryptography>=41.0.0",
            "python-whois>=0.8.0",
            "shodan>=1.30.0",
            "dnspython>=2.4.0",
            "pysnmp>=4.4.12",
            "mysql-connector-python>=8.2.0",
            "psycopg2-binary>=2.9.9",  # PostgreSQL
            "pycryptodome>=3.19.0",
            "python-nmap>=0.7.6",
        ],
    },
    entry_points={
        "console_scripts": [
            "aptes=aptes.aptes:main",
        ],
    },
    cmdclass={
        'install_system_deps': InstallSystemDepsCommand,
    },
)
