#!/usr/bin/env python3
"""
Scanner implementations for APTES
"""

import logging
import subprocess
import socket
from utils import network, parsers

logger = logging.getLogger('aptes.scanners')

def nmap_scan(target, scan_type="fast", ports=None):
    """
    Perform an nmap scan
    
    Args:
        target (str): Target to scan
        scan_type (str): Type of scan (fast, service, vuln)
        ports (str): Ports to scan
    
    Returns:
        dict: Scan results
    """
    logger.info(f"Starting {scan_type} nmap scan on {target}")
    
    # Build nmap command based on scan type
    if scan_type == "fast":
        cmd = f"nmap -F -T4 {target} -oX -"
    elif scan_type == "service":
        port_spec = f"-p {ports}" if ports else ""
        cmd = f"nmap -sV -T4 --script=banner {target} {port_spec} -oX -"
    elif scan_type == "vuln":
        port_spec = f"-p {ports}" if ports else ""
        cmd = f"nmap -sV --script=vuln {target} {port_spec} -oX -"
    else:
        # Default scan
        cmd = f"nmap -T4 {target} -oX -"
    
    try:
        output = network.run_command(cmd)
        
        if output:
            results = parsers.parse_nmap_xml(output)
            return results
        else:
            logger.error("No output from nmap scan")
            return {}
    except Exception as e:
        logger.error(f"Error in nmap scan: {str(e)}")
        
        # Fallback to simple port scan if nmap fails
        if scan_type == "fast":
            logger.info("Falling back to simple TCP port scan")
            return {target: {"tcp": network.simple_port_scan(target)}}
        else:
            return {"error": str(e)}

def web_scan(target, port=80, ssl=False):
    """
    Perform a web scan
    
    Args:
        target (str): Target to scan
        port (int): Port to scan
        ssl (bool): Use SSL/TLS
    
    Returns:
        dict: Scan results
    """
    logger.info(f"Performing web scan on {target}:{port}")
    
    protocol = "https" if ssl else "http"
    url = f"{protocol}://{target}:{port}"
    
    try:
        import requests
        
        results = {
            "url": url,
            "headers": {},
            "status_code": 0,
            "technologies": [],
            "interesting_files": []
        }
        
        # Request the main page
        response = requests.get(url, timeout=10, verify=False)
        results["status_code"] = response.status_code
        results["headers"] = dict(response.headers)
        
        # Extract technologies
        if "X-Powered-By" in response.headers:
            results["technologies"].append(response.headers["X-Powered-By"])
        if "Server" in response.headers:
            results["technologies"].append(response.headers["Server"])
        
        # Check for robots.txt
        try:
            robots = requests.get(f"{url}/robots.txt", timeout=5, verify=False)
            if robots.status_code == 200:
                results["interesting_files"].append({
                    "url": f"{url}/robots.txt",
                    "content": robots.text[:500] 
                })
        except Exception:
            pass
        
        # Check for sitemap.xml
        try:
            sitemap = requests.get(f"{url}/sitemap.xml", timeout=5, verify=False)
            if sitemap.status_code == 200:
                results["interesting_files"].append({
                    "url": f"{url}/sitemap.xml",
                    "content": "Sitemap found"
                })
        except Exception:
            pass
        
        return results
    except ImportError:
        logger.error("Requests library not available")
        return {"error": "Requests library not available"}
    except Exception as e:
        logger.error(f"Error in web scan: {str(e)}")
        return {"error": str(e)}

def subdomain_scan(domain, techniques=None):
    """
    Scan for subdomains
    
    Args:
        domain (str): Domain to scan
        techniques (list): Techniques to use
    
    Returns:
        list: Discovered subdomains
    """
    logger.info(f"Scanning for subdomains of {domain}")
    
    if techniques is None:
        techniques = ["crt.sh", "subfinder", "dnsrecon"]
    
    subdomains = set()
    
    # Certificate transparency logs (crt.sh)
    if "crt.sh" in techniques:
        try:
            import requests
            response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    domain_name = entry['name_value'].lower()
                    # Filter out wildcard entries
                    if not domain_name.startswith("*"):
                        subdomains.add(domain_name)
        except Exception as e:
            logger.debug(f"Error in crt.sh lookup: {str(e)}")
    
    # Subfinder tool
    if "subfinder" in techniques:
        try:
            cmd = f"subfinder -d {domain} -silent"
            output = network.run_command(cmd)
            if output:
                for subdomain in output.strip().split('\n'):
                    subdomains.add(subdomain.strip().lower())
        except Exception as e:
            logger.debug(f"Error using subfinder: {str(e)}")
    
    # DNSrecon tool
    if "dnsrecon" in techniques:
        try:
            cmd = f"dnsrecon -d {domain} -t brt"
            output = network.run_command(cmd)
            if output:
                # Extract domains from dnsrecon output
                import re
                domain_matches = re.findall(r"([a-zA-Z0-9\-\.]+\.{0})".format(domain), output)
                for subdomain in domain_matches:
                    subdomains.add(subdomain.strip().lower())
        except Exception as e:
            logger.debug(f"Error using dnsrecon: {str(e)}")
    
    # Convert to list and sort
    return sorted(list(subdomains))
