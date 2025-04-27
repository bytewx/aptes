#!/usr/bin/env python3
"""
Parsing utilities for APTES
"""

import re
import logging

logger = logging.getLogger('aptes.parsers')

def parse_nmap_xml(xml_data):
    """
    Parse nmap XML output to extract port and service information
    
    Args:
        xml_data (str): nmap XML output
    
    Returns:
        dict: Parsed results with host, port, and service data
    """
    results = {}
    
    host_blocks = re.findall(r"<host.*?</host>", xml_data, re.DOTALL)
    
    for host_block in host_blocks:
        addr_match = re.search(r'<address addr="([^"]*)"', host_block)
        if addr_match:
            host = addr_match.group(1)
            results[host] = {"tcp": {}}
            
            port_blocks = re.findall(r"<port.*?</port>", host_block, re.DOTALL)
            for port_block in port_blocks:
                port_match = re.search(r'portid="([^"]*)"', port_block)
                proto_match = re.search(r'protocol="([^"]*)"', port_block)
                state_match = re.search(r'<state state="([^"]*)"', port_block)
                service_match = re.search(r'<service name="([^"]*)"', port_block)
                product_match = re.search(r'product="([^"]*)"', port_block)
                version_match = re.search(r'version="([^"]*)"', port_block)
                
                if port_match and proto_match and state_match:
                    port = port_match.group(1)
                    proto = proto_match.group(1)
                    
                    if proto not in results[host]:
                        results[host][proto] = {}
                        
                    results[host][proto][port] = {
                        "port": port,
                        "state": state_match.group(1),
                        "service": service_match.group(1) if service_match else "unknown"
                    }
                    
                    if product_match:
                        results[host][proto][port]["product"] = product_match.group(1)
                    if version_match:
                        results[host][proto][port]["version"] = version_match.group(1)
                    
                    script_blocks = re.findall(r"<script.*?</script>", port_block, re.DOTALL)
                    if script_blocks:
                        scripts = {}
                        for script_block in script_blocks:
                            script_id_match = re.search(r'id="([^"]*)"', script_block)
                            script_output_match = re.search(r'output="([^"]*)"', script_block)
                            if script_id_match and script_output_match:
                                scripts[script_id_match.group(1)] = script_output_match.group(1)
                        
                        if scripts:
                            results[host][proto][port]["scripts"] = scripts
    
    return results

def parse_nmap_aggressive_output(output):
    """
    Parse the output from an aggressive Nmap scan (-T4 -A -v)
    
    Args:
        output (str): Raw output from aggressive Nmap scan
        
    Returns:
        dict: Parsed results including ports, services, and OS info
    """
    results = {
        "ports": {},
        "services": {},
        "os_info": {}
    }
    
    if not output:
        return results
    
    # Extract host information
    host_blocks = re.findall(r"Nmap scan report for ([^\s]+)(?:\s+\(([^\)]+)\))?\n.*?(?=Nmap scan report for|\Z)", 
                            output, re.DOTALL)
    
    for host_block in host_blocks:
        host_name = host_block[0]
        host_ip = host_block[1] if host_block[1] else host_name
        
        # Initialize host entries in results
        if host_ip not in results["ports"]:
            results["ports"][host_ip] = {"tcp": {}, "udp": {}}
        
        if host_ip not in results["services"]:
            results["services"][host_ip] = {"tcp": {}, "udp": {}}
        
        # Extract port information
        port_lines = re.findall(r"(\d+)/(\w+)\s+(\w+)\s+([^\n]+)", output)
        
        for port_info in port_lines:
            port, proto, state, service_info = port_info
            
            # Parse service information
            service = "unknown"
            product = ""
            version = ""
            
            service_match = re.search(r"([^\s]+)(?:\s+(.+))?", service_info)
            if service_match:
                service = service_match.group(1)
                extra_info = service_match.group(2) if service_match.group(2) else ""
                
                # Extract product and version if available
                product_match = re.search(r"([^\d]+)(?:\s+(\d[^\s]*))?", extra_info)
                if product_match:
                    product = product_match.group(1).strip()
                    version = product_match.group(2) if product_match.group(2) else ""
            
            # Add to results
            results["ports"][host_ip][proto][port] = {
                "port": port,
                "state": state,
                "service": service
            }
            
            if product:
                results["ports"][host_ip][proto][port]["product"] = product
            if version:
                results["ports"][host_ip][proto][port]["version"] = version
            
            # Add to services
            results["services"][host_ip][proto][port] = results["ports"][host_ip][proto][port].copy()
        
        # Extract OS information
        os_match = re.search(r"OS details: ([^\n]+)", output)
        if os_match:
            results["os_info"]["details"] = os_match.group(1).strip()
            
        os_cpe_match = re.search(r"OS CPE: ([^\n]+)", output)
        if os_cpe_match:
            results["os_info"]["cpe"] = os_cpe_match.group(1).strip()
    
    return results

def parse_dns_results(output, record_type):
    """
    Parse DNS results from command output
    
    Args:
        output (str): Command output with DNS results
        record_type (str): DNS record type (A, MX, etc.)
    
    Returns:
        list: List of DNS records
    """
    if not output:
        return []
    
    records = output.strip().split('\n')
    cleaned_records = []
    
    # Process based on record type
    if record_type in ["A", "AAAA"]:
        # Simple IP addresses
        for record in records:
            if re.match(r'\d+\.\d+\.\d+\.\d+', record):
                cleaned_records.append(record)
    elif record_type == "MX":
        # Extract MX records with priority
        for record in records:
            # MX records may have priority (e.g., "10 mail.example.com")
            mx_match = re.match(r'(\d+)\s+(.+)', record)
            if mx_match:
                cleaned_records.append({
                    "priority": mx_match.group(1),
                    "server": mx_match.group(2)
                })
            else:
                cleaned_records.append(record)
    else:
        # Other record types
        cleaned_records = records
    
    return cleaned_records

def parse_ssl_cert_info(output):
    """
    Parse SSL certificate information from openssl output
    
    Args:
        output (str): Output from openssl command
    
    Returns:
        dict: Parsed SSL certificate information
    """
    result = {}
    
    if not output:
        return result
    
    # Extract issuer
    issuer_match = re.search(r"Issuer:.*?=(.*?)[,\n]", output)
    if issuer_match:
        result["issuer"] = issuer_match.group(1).strip()
    
    # Extract expiry date
    expiry_match = re.search(r"Not After\s*:\s*(.*?)\n", output)
    if expiry_match:
        result["expiry"] = expiry_match.group(1).strip()
    
    # Extract subject alternative names
    alt_names = []
    alt_name_match = re.search(r"Subject Alternative Name.*?:(.*?)(?:\n\n|\n[^\s])", output, re.DOTALL)
    if alt_name_match:
        alt_names_text = alt_name_match.group(1)
        dns_matches = re.findall(r"DNS:(.*?)(?:,|$)", alt_names_text)
        alt_names.extend([name.strip() for name in dns_matches])
        
    if alt_names:
        result["alt_names"] = alt_names
    
    return result

def parse_netbios_output(output):
    """
    Parse output from NetBIOS scan
    
    Args:
        output (str): Output from nbtscan command
    
    Returns:
        dict: NetBIOS information by IP address
    """
    result = {}
    
    if not output:
        return result
    
    lines = output.strip().split('\n')
    
    for line in lines:
        # Look for IP and NetBIOS name
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+(\S+)(?:\s+(.+))?", line)
        if match:
            ip = match.group(1)
            netbios_name = match.group(2)
            extra_info = match.group(3) if match.group(3) else ""
            
            result[ip] = {
                "name": netbios_name,
                "info": extra_info
            }
    
    return result

def extract_urls_from_html(html_content):
    """
    Extract URLs from HTML content
    
    Args:
        html_content (str): HTML content
    
    Returns:
        list: List of extracted URLs
    """
    urls = []
    
    # Extract href attributes
    href_matches = re.findall(r'href=["\'](https?://[^"\'>]+)["\']', html_content)
    urls.extend(href_matches)
    
    # Extract src attributes
    src_matches = re.findall(r'src=["\'](https?://[^"\'>]+)["\']', html_content)
    urls.extend(src_matches)
    
    # Remove duplicates
    return list(set(urls))
