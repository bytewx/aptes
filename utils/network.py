#!/usr/bin/env python3
"""
Network utilities for APTES
"""

import socket
import re
import subprocess
import logging

logger = logging.getLogger('aptes.network')

def is_ip_address(address):
    """
    Check if the given address is an IP address
    
    Args:
        address (str): Address to check
    
    Returns:
        bool: True if address is an IP address, False otherwise
    """
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False

def resolve_domain(domain):
    """
    Resolve domain to IP address
    
    Args:
        domain (str): Domain to resolve
    
    Returns:
        str: IP address or None if resolution fails
    """
    try:
        ip_address = socket.gethostbyname(domain)
        logger.debug(f"Resolved {domain} to {ip_address}")
        return ip_address
    except socket.gaierror:
        logger.debug(f"Failed to resolve {domain}")
        return None

def simple_port_scan(target, ports=None):
    """
    Perform a simple TCP port scan
    
    Args:
        target (str): Target host or IP address
        ports (list): List of ports to scan, defaults to common ports
    
    Returns:
        dict: Dictionary of open ports and their services
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    results = {}
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = guess_service(port)
                results[str(port)] = {
                    "port": str(port),
                    "state": "open",
                    "service": service
                }
            sock.close()
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {str(e)}")
    
    return results

def guess_service(port):
    """
    Guess service based on port number
    
    Args:
        port (int): Port number
    
    Returns:
        str: Service name or 'unknown'
    """
    service_map = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "domain",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        993: "imaps",
        995: "pop3s",
        1723: "pptp",
        3306: "mysql",
        3389: "ms-wbt-server",
        5900: "vnc",
        8080: "http-proxy"
    }
    return service_map.get(port, "unknown")

def run_command(command, shell=True, timeout=60):
    """
    Run a shell command and return the output
    
    Args:
        command (str): Command to run
        shell (bool): Whether to use shell
        timeout (int): Command timeout in seconds
    
    Returns:
        str: Command output or empty string on error
    """
    try:
        output = subprocess.check_output(
            command, 
            shell=shell, 
            timeout=timeout,
            stderr=subprocess.STDOUT
        ).decode('utf-8', errors='ignore')
        return output
    except subprocess.SubprocessError as e:
        logger.debug(f"Command execution error: {str(e)}")
        return ""