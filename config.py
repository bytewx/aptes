#!/usr/bin/env python3
"""
Configuration management for APTES
"""

import os
import json
from pathlib import Path
from datetime import datetime

class Config:
    """Configuration class for APTES"""
    
    def __init__(self, target=None, output_dir="reports", threads=3, verbosity=1, verify_ssl=True):
        """Initialize the configuration"""
        self.target = target
        self.output_dir = output_dir
        self.threads = threads
        self.verbosity = verbosity
        self.verify_ssl = verify_ssl
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Initialize results dictionary
        self.results = {
            "target": target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "recon": {},
            "preexploit": {},
            "exploit": {},
            "postexploit": {}
        }
    
    def save_results(self, filename=None):
        """Save all results to a JSON file"""
        if filename is None:
            # Create a default filename based on target and timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_safe = self.target.replace(".", "_").replace(":", "_")
            filename = f"{self.output_dir}/{target_safe}_{timestamp}.json"
        
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=4)
        
        return filename
    
    def load_results(self, filename):
        """Load results from a JSON file"""
        try:
            with open(filename, "r") as f:
                data = json.load(f)
            
            # Update results with loaded data
            self.results.update(data)
            
            # Set target if not already set
            if not self.target and "target" in data:
                self.target = data["target"]
            
            return True
        except Exception as e:
            return False
    
    @staticmethod
    def get_base_dir():
        """Get the base directory of the APTES installation"""
        return Path(__file__).parent.absolute()
    
    @staticmethod
    def get_data_dir():
        """Get the data directory of the APTES installation"""
        return Path(__file__).parent.absolute() / 'data'