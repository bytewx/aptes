#!/usr/bin/env python3
"""
Setup script for APTES package
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

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
        "requests",
        "urllib3",
    ],
    extras_require={
        "reports": ["openpyxl"],
        "full": ["openpyxl", "scrapy", "concurrent.futures"],
        "webcrawl": ["scrapy"],
    },
    entry_points={
        "console_scripts": [
            "aptes=aptes.aptes:main",
        ],
    },
)
