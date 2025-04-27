#!/usr/bin/env python3
"""
Logging utilities for APTES
"""

import logging
from datetime import datetime

def setup_logger(name='aptes', verbosity=1):
    """
    Configure and return a logger with the specified verbosity level
    
    Args:
        name (str): Logger name
        verbosity (int): Verbosity level (0=quiet, 1=normal, 2=verbose)
    
    Returns:
        logging.Logger: Configured logger
    """
    # Configure logging format
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        format=log_format,
        level=logging.INFO
    )
    
    logger = logging.getLogger(name)
    
    # Set verbosity level
    if verbosity >= 2:
        logger.setLevel(logging.DEBUG)
    elif verbosity == 1:
        logger.setLevel(logging.INFO)
    elif verbosity == 0:
        logger.setLevel(logging.WARNING)
    
    return logger

def setup_file_logger(name='aptes', log_file=None, verbosity=1):
    """
    Configure and return a logger that writes to both console and file
    
    Args:
        name (str): Logger name
        log_file (str): Path to log file
        verbosity (int): Verbosity level (0=quiet, 1=normal, 2=verbose)
    
    Returns:
        logging.Logger: Configured logger
    """
    logger = setup_logger(name, verbosity)
    
    # Set up default log file if none provided
    if log_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"aptes_{timestamp}.log"
    
    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    # Set appropriate level for file handler
    if verbosity >= 2:
        file_handler.setLevel(logging.DEBUG)
    elif verbosity == 1:
        file_handler.setLevel(logging.INFO)
    elif verbosity == 0:
        file_handler.setLevel(logging.WARNING)
    
    # Add file handler to logger
    logger.addHandler(file_handler)
    
    return logger