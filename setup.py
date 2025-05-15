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
    "hydra": "Login cracker"
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
    version="1.0.0",
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
    ],
    python_requires=">=3.6",
    install_requires=[
        "requests>=2.25.0",
        "urllib3>=1.26.0",
        "beautifulsoup4>=4.9.0",
        "lxml>=4.6.0",
    ],
    extras_require={
        "reports": ["openpyxl>=3.0.0"],
        "ssh": ["paramiko>=2.7.0"],
        "webcrawl": [
            "scrapy>=2.5.0", 
            "pyopenssl>=20.0.0",
            "twisted>=21.2.0",
            "cryptography>=3.4.0",
        ],
        "full": [
            "openpyxl>=3.0.0",
            "scrapy>=2.5.0",
            "paramiko>=2.7.0",
            "pyopenssl>=20.0.0",
            "twisted>=21.2.0",
            "cryptography>=3.4.0",
            "python-whois>=0.7.0",
            "shodan>=1.25.0",
            "dnspython>=2.1.0",
            "pysnmp>=4.4.0",
            "mysql-connector-python>=8.0.0",
            "psycopg2-binary>=2.9.0",  # PostgreSQL
            "pycrypto>=2.6.0",
            "python-nmap>=0.7.0",
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
