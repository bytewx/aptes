#!/usr/bin/env python3
"""
Reconnaissance phase module for APTES
"""

import time
import subprocess
import logging
from datetime import datetime

from phases.base import PhaseBase
from lib import scanners
from utils import network
from utils import parsers

# Check for optional imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import concurrent.futures
    CONCURRENT_AVAILABLE = True
except ImportError:
    CONCURRENT_AVAILABLE = False

# Common port to service mapping for enhanced service identification
PORT_NUMBERS = {
    '13': 'Daytime', '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP',
    '37': 'Time', '53': 'DNS', '67': 'DHCP', '70': 'Gopher', '79': 'Finger',
    '80': 'HTTP', '110': 'POP3', '111': 'NFS', '123': 'NTP', '137': 'NetBios',
    '139': 'SMB', '143': 'IMAP', '161': 'SNMP', '389': 'LDAP', '443': 'HTTPS',
    '445': 'SMB', '500': 'Ike', '523': 'Db2', '524': 'Novel Netware', '548': 'AFP',
    '554': 'RTSP', '631': 'CUPS', '636': 'LDAP/S', '873': 'Rsync', '993': 'IMAP/S',
    '995': 'POP3/S', '1050': 'COBRA', '1080': 'SOCKS', '1099': 'RMI Registry',
    '1344': 'ICAP', '1352': 'Lotus Domino', '1433': 'MS-SQL', '1434': 'MS-SQL/UDP',
    '1521': 'Oracle', '1604': 'Citrix', '1723': 'PPTP', '2202': 'ACARS',
    '2302': 'Freelancer', '2628': 'DICT', '2947': 'GPS', '3031': 'Apple Remote Event',
    '3260': 'iSCSI', '3306': 'MySQL', '3389': 'Remote Desktop', '3478': 'STUN',
    '3632': 'Compiler Deaemon', '4369': 'Erlang Port Mapper', '5019': 'Versant',
    '5060': 'SIP', '5353': 'DNS Service Discovery', '5666': 'Nagios', '5672': 'AMQP',
    '5850': 'Open Lookup', '5900': 'VNC', '5984': 'CouchDb', '6000': 'X11',
    '6379': 'Redis', '6481': 'Sun Service Tag', '6666': 'Voldemort', '7210': 'MaxDb',
    '7634': 'HD Info', '8000': 'QNX QCONN', '8009': 'AJP', '8080': 'HTTP-ALT',
    '8081': 'McAfee ePO', '8091': 'CoucheBase Web Administration', '8332': 'Bitcoin',
    '8333': 'Bitcoin', '8443': 'HTTPS-ALT', '9100': 'Lexmark', '9160': 'Cassandra',
    '9999': 'Java Debug Wire Protocol', '10000': 'Network Data Management',
    '11211': 'Memory Object Caching', '12000': 'CCCAM', '12345': 'NetBus',
    '17185': 'VxWorks', '19150': 'GKRe11M', '27017': 'MongoDb', '31337': 'BackOrifice',
    '35871': 'Flume', '50000': 'DRDA', '50030': 'Hadoop', '50060': 'Hadoop',
    '50070': 'Hadoop', '50075': 'Hadoop', '50090': 'Hadoop', '60010': 'Apache HBase',
    '60030': 'Apache HBase'
}

class ReconnaissancePhase(PhaseBase):
    """Reconnaissance Phase Controller"""
    
    def __init__(self, framework):
        """Initialize the Reconnaissance phase controller"""
        super().__init__(framework)
        
        # Initialize phase-specific results
        self.results.update({
            "passive": {},
            "active": {}
        })
    
    def _execute(self, passive_only=False, skip_web=False):
        """
        Execute reconnaissance phase operations
        
        Args:
            passive_only (bool): Only perform passive reconnaissance
            skip_web (bool): Skip web scanning
        """
        self.logger.info(f"Running reconnaissance on {self.target}")
        
        # Perform passive reconnaissance
        self.passive_recon()
        
        # Perform active reconnaissance if not passive only
        if not passive_only:
            self.active_recon(skip_web=skip_web)
        
        return self.results
    
    def passive_recon(self):
        """Perform passive reconnaissance"""
        self.logger.info("Starting passive reconnaissance")
        
        # Check if we have concurrent futures for parallel execution
        if CONCURRENT_AVAILABLE:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                dns_future = executor.submit(self.dns_lookup)
                subdomain_future = executor.submit(self.subdomain_enum)
                ssl_future = executor.submit(self.ssl_info)
                
                self.results["passive"]["dns"] = dns_future.result()
                self.results["passive"]["subdomains"] = subdomain_future.result()
                self.results["passive"]["ssl_info"] = ssl_future.result()
        else:
            # Sequential execution if concurrent not available
            self.results["passive"]["dns"] = self.dns_lookup()
            self.results["passive"]["subdomains"] = self.subdomain_enum()
            self.results["passive"]["ssl_info"] = self.ssl_info()
        
        self.logger.info("Passive reconnaissance completed")
        return self.results["passive"]
    
    def active_recon(self, skip_web=False):
        """
        Perform active reconnaissance
        
        Args:
            skip_web (bool): Skip web scanning
        """
        self.logger.info("Starting active reconnaissance")
        
        # Check if we have concurrent futures for parallel execution
        if CONCURRENT_AVAILABLE:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                port_scan_future = executor.submit(self.port_scan)
                service_enum_future = executor.submit(self.service_enum)
                vuln_scan_future = executor.submit(self.vuln_scan)
                
                self.results["active"]["ports"] = port_scan_future.result()
                self.results["active"]["services"] = service_enum_future.result()
                self.results["active"]["vulnerabilities"] = vuln_scan_future.result()
        else:
            # Sequential execution if concurrent not available
            self.results["active"]["ports"] = self.port_scan()
            self.results["active"]["services"] = self.service_enum()
            self.results["active"]["vulnerabilities"] = self.vuln_scan()
        
        # Perform web scanning if not skipped
        if not skip_web:
            self.results["active"]["web"] = self.web_scan()
        
        self.logger.info("Active reconnaissance completed")
        return self.results["active"]
    
    def dns_lookup(self):
        """
        Perform DNS lookups
        
        Returns:
            dict: DNS records by type
        """
        self.logger.info(f"Performing DNS lookups for {self.target}")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
        results = {}
        
        for record_type in record_types:
            try:
                cmd = f"dig +short {self.target} {record_type}"
                output = network.run_command(cmd)
                
                if output:
                    parsed_records = parsers.parse_dns_results(output, record_type)
                    results[record_type] = parsed_records
                else:
                    results[record_type] = []
            except Exception as e:
                self.logger.debug(f"Error in DNS lookup for {record_type}: {str(e)}")
                results[record_type] = []
                
        return results
    
    def subdomain_enum(self):
        """
        Enumerate subdomains
        
        Returns:
            list: Discovered subdomains
        """
        self.logger.info(f"Enumerating subdomains for {self.target}")
        subdomains = set()
        
        # Try to use crt.sh for subdomain enumeration
        if REQUESTS_AVAILABLE:
            try:
                response = requests.get(f"https://crt.sh/?q=%.{self.target}&output=json", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        domain_name = entry['name_value']
                        subdomains.add(domain_name)
            except Exception as e:
                self.logger.debug(f"Error in crt.sh lookup: {str(e)}")
        
        # Try to use subfinder if available
        try:
            cmd = f"subfinder -d {self.target} -silent"
            output = network.run_command(cmd)
            if output:
                for subdomain in output.split('\n'):
                    subdomains.add(subdomain.strip())
        except Exception as e:
            self.logger.debug(f"Error using subfinder: {str(e)}")
        
        # Try to use dnsrecon if available
        try:
            cmd = f"dnsrecon -d {self.target} -t brt"
            output = network.run_command(cmd)
            if output:
                # Extract domains from dnsrecon output
                import re
                domain_matches = re.findall(r"([a-zA-Z0-9\-\.]+\.{0})".format(self.target), output)
                for domain in domain_matches:
                    subdomains.add(domain.strip())
        except Exception as e:
            self.logger.debug(f"Error using dnsrecon: {str(e)}")
            
        return list(subdomains)
    
    def ssl_info(self):
        """
        Gather SSL certificate information
        
        Returns:
            dict: SSL certificate details
        """
        self.logger.info(f"Gathering SSL certificate information for {self.target}")
        try:
            cmd = f"echo | openssl s_client -servername {self.target} -connect {self.target}:443 2>/dev/null | openssl x509 -noout -text"
            output = network.run_command(cmd)
            
            if output:
                return parsers.parse_ssl_cert_info(output)
            else:
                return {}
        except Exception as e:
            self.logger.debug(f"Error gathering SSL info: {str(e)}")
            return {"error": str(e)}
    
    def port_scan(self):
        """
        Perform port scanning with service identification
        
        Returns:
            dict: Open ports and services with descriptions
        """
        self.logger.info(f"Scanning ports on {self.target}")
        try:
            # Use nmap scanner from lib
            results = scanners.nmap_scan(self.target, scan_type="fast")
            
            # Enhance results with service descriptions from PORT_NUMBERS
            for host, protocols in results.items():
                for protocol, ports in protocols.items():
                    for port_num, port_info in ports.items():
                        # Add service description if available
                        port_str = str(port_num)
                        if port_str in PORT_NUMBERS:
                            port_info['service_description'] = PORT_NUMBERS[port_str]
                        
            return results
        except Exception as e:
            self.logger.error(f"Error in port scanning: {str(e)}")
            
            # Fallback to simple TCP port scan if nmap fails
            self.logger.info("Falling back to simple TCP port scan")
            results = {self.target: {"tcp": {}}}
            
            # Perform simple port scan
            open_ports = network.simple_port_scan(self.target)
            
            # Add port info with service descriptions
            for port in open_ports:
                port_str = str(port)
                results[self.target]["tcp"][port] = {
                    "state": "open",
                    "reason": "simple_scan",
                    "service": PORT_NUMBERS.get(port_str, "unknown")
                }
                if port_str in PORT_NUMBERS:
                    results[self.target]["tcp"][port]["service_description"] = PORT_NUMBERS[port_str]
            
            return results
    
    def service_enum(self):
        """
        Enumerate services on open ports with enhanced descriptions
        
        Returns:
            dict: Service details with descriptions
        """
        self.logger.info(f"Enumerating services on {self.target}")
        try:
            # Resolve domain to IP if needed
            target_ip = self.target
            if not network.is_ip_address(self.target):
                resolved_ip = network.resolve_domain(self.target)
                if resolved_ip:
                    target_ip = resolved_ip
            
            # Build port list from common port numbers dictionary
            # Use common service ports from PORT_NUMBERS plus standard web ports
            common_ports = list(PORT_NUMBERS.keys())
            port_list = ",".join(common_ports)
            
            # Use nmap for service detection
            results = scanners.nmap_scan(target_ip, scan_type="service", ports=port_list)
            
            # Enhance results with service descriptions
            for host, protocols in results.items():
                for protocol, ports in protocols.items():
                    for port_num, port_info in ports.items():
                        # Add service description if available
                        port_str = str(port_num)
                        if port_str in PORT_NUMBERS:
                            port_info['service_description'] = PORT_NUMBERS[port_str]
                            # Add common vulnerabilities for this service type
                            port_info['common_vulnerabilities'] = self._get_common_vulnerabilities(PORT_NUMBERS[port_str])
                        
            return results
        except Exception as e:
            self.logger.error(f"Error in service enumeration: {str(e)}")
            return {"error": str(e)}
    
    def _get_common_vulnerabilities(self, service_name):
        """
        Get common vulnerabilities for a specific service
        
        Args:
            service_name (str): Service name
            
        Returns:
            list: Common vulnerabilities for the service
        """
        # Dictionary of common vulnerabilities by service
        common_vulns = {
            'FTP': ['Anonymous login', 'Brute force', 'Clear-text credentials', 'Directory traversal'],
            'SSH': ['Brute force', 'Outdated version vulnerabilities', 'Key-based authentication issues'],
            'Telnet': ['Clear-text credentials', 'No encryption', 'Brute force'],
            'SMTP': ['Open relay', 'User enumeration', 'STARTTLS issues'],
            'DNS': ['Zone transfer', 'Cache poisoning', 'Amplification attacks'],
            'HTTP': ['SQL injection', 'XSS', 'CSRF', 'Directory traversal', 'File inclusion'],
            'HTTPS': ['SSL/TLS vulnerabilities', 'Weak ciphers', 'Certificate issues'],
            'SMB': ['EternalBlue', 'SMB signing disabled', 'Null session'],
            'MySQL': ['Weak credentials', 'Configuration issues', 'Privilege escalation'],
            'Remote Desktop': ['BlueKeep', 'Brute force', 'Man-in-the-middle'],
            'VNC': ['Authentication bypass', 'Brute force', 'Encryption issues'],
            'MongoDB': ['Unauthenticated access', 'Data exposure', 'Injection attacks']
        }
        
        return common_vulns.get(service_name, ['No common vulnerabilities information available'])
    
    def vuln_scan(self):
        """
        Perform vulnerability scanning with port service context
        
        Returns:
            dict: Detected vulnerabilities
        """
        self.logger.info(f"Checking for vulnerabilities on {self.target}")
        try:
            # Resolve domain to IP if needed
            target_ip = self.target
            if not network.is_ip_address(self.target):
                resolved_ip = network.resolve_domain(self.target)
                if resolved_ip:
                    target_ip = resolved_ip
            
            # Build a list of ports to scan based on our PORT_NUMBERS dictionary
            # Focus on commonly vulnerable services
            vulnerable_services = ['21', '22', '23', '25', '53', '80', '110', '111', '139', 
                                  '143', '161', '389', '443', '445', '1433', '3306', '3389', 
                                  '5432', '5900', '6379', '8080', '8443', '27017']
            port_list = ",".join(vulnerable_services)
            
            # Use nmap with vulnerability scripts
            results = scanners.nmap_scan(target_ip, scan_type="vuln", ports=port_list)
            
            # Extract vulnerabilities from results
            vulns = []
            for host_data in results.values():
                for proto_data in host_data.values():
                    for port_data in proto_data.values():
                        port_num = port_data.get("port", "unknown")
                        service = port_data.get("service", "unknown")
                        
                        # Add service description from PORT_NUMBERS
                        port_str = str(port_num)
                        service_desc = PORT_NUMBERS.get(port_str, "Unknown Service")
                        
                        scripts = port_data.get("scripts", {})
                        for script_name, script_output in scripts.items():
                            if "VULNERABLE" in script_output:
                                vulns.append({
                                    "port": port_num,
                                    "service": service,
                                    "service_description": service_desc,
                                    "vulnerability": script_name,
                                    "details": script_output,
                                    "severity": self._estimate_severity(script_name, script_output)
                                })
            
            return {
                "vulnerabilities": vulns, 
                "scan_data": results,
                "summary": {
                    "total_vulns": len(vulns),
                    "by_severity": self._count_by_severity(vulns),
                    "by_service": self._count_by_service(vulns)
                }
            }
        except Exception as e:
            self.logger.error(f"Error in vulnerability scanning: {str(e)}")
            return {"error": str(e)}
    
    def _estimate_severity(self, script_name, output):
        """
        Estimate vulnerability severity based on script name and output
        
        Args:
            script_name (str): Name of the vulnerability script
            output (str): Script output
            
        Returns:
            str: Estimated severity (Critical, High, Medium, Low, Info)
        """
        # Keywords that might indicate severity
        critical_keywords = ["remote code execution", "RCE", "critical", "arbitrary code"]
        high_keywords = ["high", "SQL injection", "XSS", "command injection", "privilege escalation"]
        medium_keywords = ["medium", "information disclosure", "CSRF", "cross-site"]
        low_keywords = ["low", "information leakage", "clickjacking"]
        
        output_lower = output.lower()
        script_lower = script_name.lower()
        
        # Check for severity indications in output and script name
        for keyword in critical_keywords:
            if keyword.lower() in output_lower or keyword.lower() in script_lower:
                return "Critical"
                
        for keyword in high_keywords:
            if keyword.lower() in output_lower or keyword.lower() in script_lower:
                return "High"
                
        for keyword in medium_keywords:
            if keyword.lower() in output_lower or keyword.lower() in script_lower:
                return "Medium"
                
        for keyword in low_keywords:
            if keyword.lower() in output_lower or keyword.lower() in script_lower:
                return "Low"
                
        return "Info"
    
    def _count_by_severity(self, vulns):
        """
        Count vulnerabilities by severity
        
        Args:
            vulns (list): List of vulnerability dictionaries
            
        Returns:
            dict: Count by severity
        """
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in vulns:
            severity = vuln.get("severity", "Info")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_service(self, vulns):
        """
        Count vulnerabilities by service
        
        Args:
            vulns (list): List of vulnerability dictionaries
            
        Returns:
            dict: Count by service
        """
        counts = {}
        for vuln in vulns:
            service = vuln.get("service_description", vuln.get("service", "Unknown"))
            counts[service] = counts.get(service, 0) + 1
        return counts
    
    def web_scan(self):
        """
        Perform web scanning with enhanced analysis of common web ports
        
        Returns:
            dict: Web scan results
        """
        self.logger.info(f"Performing web scan on {self.target}")
        
        if not REQUESTS_AVAILABLE:
            self.logger.error("Requests library not available, skipping web scan")
            return {"error": "Requests library not available"}
        
        results = {
            "headers": {},
            "technologies": [],
            "interesting_files": [],
            "security_headers": {}
        }
        
        # Web ports from PORT_NUMBERS
        web_ports = [80, 443, 8080, 8443]
        
        # Add more web ports commonly used
        for port_str in PORT_NUMBERS:
            port_int = int(port_str)
            if PORT_NUMBERS[port_str] in ["HTTP", "HTTPS", "HTTP-ALT", "HTTPS-ALT"] and port_int not in web_ports:
                web_ports.append(port_int)
        
        for port in web_ports:
            protocol = "https" if port in [443, 8443] or "HTTPS" in PORT_NUMBERS.get(str(port), "") else "http"
            url = f"{protocol}://{self.target}:{port}"
            
            try:
                response = requests.get(url, timeout=10, verify=self.verify_ssl)
                
                results["headers"][f"{url}"] = dict(response.headers)
                
                # Identify technologies
                self._identify_web_technologies(response, results)
                
                # Check security headers
                self._check_security_headers(response, port, results)
                
                # Check for common files
                self._check_common_files(url, results)
                
            except requests.exceptions.RequestException:
                continue
                
        return results
    
    def _identify_web_technologies(self, response, results):
        """
        Identify web technologies from HTTP response
        
        Args:
            response: HTTP response object
            results: Results dictionary to update
        """
        # Check headers for technology indicators
        headers = response.headers
        
        if "X-Powered-By" in headers:
            results["technologies"].append(headers["X-Powered-By"])
        if "Server" in headers:
            results["technologies"].append(headers["Server"])
        if "X-AspNet-Version" in headers:
            results["technologies"].append(f"ASP.NET {headers['X-AspNet-Version']}")
        if "X-Runtime" in headers:
            results["technologies"].append(f"Ruby {headers['X-Runtime']}")
        
        # Check response content for technology indicators
        content = response.text.lower()
        
        # Check for common web frameworks and technologies
        tech_signatures = {
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "drupal": ["drupal.min.js", "drupal.js", "drupal.settings"],
            "joomla": ["joomla!", "/components/com_", "window.joomla"],
            "laravel": ["laravel", "laravel.csrf"],
            "django": ["csrftoken", "__admin_media_prefix__", "django"],
            "angular": ["ng-app", "angular.js", "angular.min.js"],
            "react": ["reactjs", "react.js", "react-dom"],
            "vue": ["vue.js", "vue.min.js", "v-bind", "v-on"]
        }
        
        for tech, signatures in tech_signatures.items():
            for signature in signatures:
                if signature in content:
                    results["technologies"].append(tech.capitalize())
                    break
    
    def _check_security_headers(self, response, port, results):
        """
        Check for security headers in HTTP response
        
        Args:
            response: HTTP response object
            port: Port number
            results: Results dictionary to update
        """
        security_headers = {
            "Strict-Transport-Security": "Missing HSTS header",
            "Content-Security-Policy": "Missing CSP header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "X-Frame-Options": "Missing X-Frame-Options header",
            "X-XSS-Protection": "Missing X-XSS-Protection header"
        }
        
        port_results = {
            "port": port,
            "service": PORT_NUMBERS.get(str(port), "web"),
            "missing_headers": []
        }
        
        for header, message in security_headers.items():
            if header not in response.headers:
                port_results["missing_headers"].append(message)
        
        results["security_headers"][f"{port}"] = port_results
    
    def _check_common_files(self, base_url, results):
        """
        Check for common files at URL
        
        Args:
            base_url: Base URL to check
            results: Results dictionary to update
        """
        common_files = [
            "robots.txt",
            "sitemap.xml",
            ".git/HEAD",
            "wp-login.php",
            "phpinfo.php",
            "admin/",
            ".env",
            "config.php",
            ".DS_Store",
            ".htaccess",
            "backup.zip",
            "wp-config.php.bak"
        ]
        
        for file in common_files:
            try:
                url = f"{base_url}/{file}"
                response = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if 200 <= response.status_code < 300:
                    results["interesting_files"].append({
                        "url": url,
                        "status_code": response.status_code,
                        "content_type": response.headers.get("Content-Type", "Unknown"),
                        "content_preview": response.text[:500] if len(response.text) > 0 else "Empty file"
                    })
            except requests.exceptions.RequestException:
                continue
