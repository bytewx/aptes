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
    # Extended port to service mapping
    port_numbers = {
        '13': 'Daytime', '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP',
        '37': 'Time', '53': 'DNS', '67': 'DHCP', '70': 'Gopher', '79': 'Finger',
        '110': 'POP3', '111': 'NFS', '123': 'NTP', '137': 'NetBios', '139': 'SMB',
        '143': 'IMAP', '161': 'SNMP', '389': 'LDAP', '445': 'SMB', '500': 'Ike',
        '523': 'Db2', '524': 'Novel Netware', '548': 'AFP', '554': 'RTSP',
        '631': 'CUPS', '636': 'LDAP/S', '873': 'Rsync', '993': 'IMAP/S', '995': 'POP3/S',
        '1050': 'COBRA', '1080': 'SOCKS', '1099': 'RMI Registry', '1344': 'ICAP', '1352': 'Lotus Domino',
        '1433': 'MS-SQL', '1434': 'MS-SQL/UDP', '1521': 'Oracle', '1604': 'Citrix', '1723': 'PPTP',
        '2202': 'ACARS', '2302': 'Freelancer', '2628': 'DICT', '2947': 'GPS', '3031': 'Apple Remote Event',
        '3260': 'iSCSI', '3306': 'MySQL', '3389': 'Remote Desktop', '3478': 'STUN', '3632': 'Compiler Deaemon',
        '4369': 'Erlang Port Mapper', '5019': 'Versant', '5060': 'SIP',
        '5353': 'DNS Service Discovery', '5666': 'Nagios', '5672': 'AMQP', '5850': 'Open Lookup', '5900': 'VNC',
        '5984': 'CouchDb', '6000': 'X11', '6379': 'Redis', '6481': 'Sun Service Tag',
        '6666': 'Voldemort', '7210': 'MaxDb', '7634': 'HD Info', '8000': 'QNX QCONN', '8009': 'AJP',
        '8081': 'McAfee ePO', '8091': 'CoucheBase Web Administration', '8332': 'Bitcoin', '8333': 'Bitcoin',
        '9100': 'Lexmark', '9160': 'Cassandra', '9999': 'Java Debug Wire Protocol', '10000': 'Network Data Management',
        '11211': 'Memory Object Caching', '1200': 'CCCAM', '12345': 'NetBus',
        '17185': 'VxWorks', '19150': 'GKRe11M', '27017': 'MongoDb', '31337': 'BackOrifice', '35871': 'Flume',
        '50000': 'DRDA', '50030': 'Hadoop', '50060': 'Hadoop', '50070': 'Hadoop',
        '50075': 'Hadoop', '50090': 'Hadoop', '60010': 'Apache HBase', '60030': 'Apache HBase'
    }
    
    port_str = str(port)
    if port_str in port_numbers:
        return port_numbers[port_str]
    return "unknown"

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

def nmap_ping_scan(target):
    """
    Run Nmap ping scan to discover live hosts
    
    Args:
        target (str): Target host, IP address, or network range
        
    Returns:
        list: List of discovered live hosts
    """
    logger.info(f"Running Nmap ping scan on {target}")
    try:
        command = f"nmap -sn {target}"
        output = run_command(command)
        
        # Parse output to extract live hosts
        live_hosts = []
        host_matches = re.findall(r"Nmap scan report for ([^\s]+)(?:\s+\(([^\)]+)\))?", output)
        
        for match in host_matches:
            if match[1]:  # IP address is in group 1 if hostname was used
                live_hosts.append(match[1])
            else:
                live_hosts.append(match[0])
                
        return live_hosts
    except Exception as e:
        logger.error(f"Error in Nmap ping scan: {str(e)}")
        return []

def netbios_scan(target):
    """
    Run NetBIOS scan to discover live hosts and NetBIOS names
    
    Args:
        target (str): Target host, IP address, or network range
        
    Returns:
        str: Raw output from nbtscan command for further parsing
    """
    logger.info(f"Running NetBIOS scan on {target}")
    try:
        command = f"nbtscan {target}"
        output = run_command(command)
        return output
    except Exception as e:
        logger.error(f"Error in NetBIOS scan: {str(e)}")
        return ""

def nmap_aggressive_scan(target):
    """
    Run Nmap aggressive TCP port scan with service detection and OS fingerprinting
    
    Args:
        target (str): Target host or IP address
        
    Returns:
        str: Raw output from nmap command for further parsing
    """
    logger.info(f"Running Nmap aggressive scan on {target}")
    try:
        command = f"nmap -T4 -A -v {target}"
        output = run_command(command, timeout=300)  # Increased timeout for aggressive scan
        return output
    except Exception as e:
        logger.error(f"Error in Nmap aggressive scan: {str(e)}")
        return ""
