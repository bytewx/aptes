#!/usr/bin/env python3
"""
Base class for APTES phases
"""

import logging
from datetime import datetime

class PhaseBase:
    """Base class for all assessment phases"""
    
    def __init__(self, framework):
        """
        Initialize the phase with a reference to the framework
        
        Args:
            framework: Reference to the main APTES framework
        """
        self.framework = framework
        self.target = framework.target
        self.output_dir = framework.output_dir
        self.threads = framework.threads
        self.verbosity = framework.verbosity
        self.verify_ssl = framework.verify_ssl
        self.logger = logging.getLogger(f'aptes.{self.__class__.__name__}')
        
        # Initialize results template
        self.results = {
            "target": self.target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def run(self, **kwargs):
        """
        Run the phase
        
        Args:
            **kwargs: Phase-specific options
        
        Returns:
            dict: Phase results
        """
        self.logger.info(f"Starting {self.__class__.__name__} phase for {self.target}")
        start_time = datetime.now()
        
        try:
            # Implementation should be provided by subclasses
            self._execute(**kwargs)
            
            # Calculate duration
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            self.results["duration"] = duration
            
            self.logger.info(f"{self.__class__.__name__} phase completed in {duration:.2f} seconds")
            return self.results
        except Exception as e:
            self.logger.error(f"Error in {self.__class__.__name__} phase: {str(e)}")
            if self.verbosity >= 2:
                import traceback
                traceback.print_exc()
            return None
    
    def _execute(self, **kwargs):
        """
        Execute the phase-specific operations
        
        This method should be implemented by subclasses.
        
        Args:
            **kwargs: Phase-specific options
        """
        raise NotImplementedError("Subclasses must implement _execute method")