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
    
    def _execute(self, passive_only=False, skip_web=False, use_ping_scan=False, use_netbios_scan=False, use_aggressive_scan=False):
        """
        Execute reconnaissance phase operations
        
        Args:
            passive_only (bool): Only perform passive reconnaissance
            skip_web (bool): Skip web scanning
            use_ping_scan (bool): Use Nmap ping scan for host discovery
            use_netbios_scan (bool): Use NetBIOS scan for host discovery
            use_aggressive_scan (bool): Use Nmap aggressive scan for port and service detection
        """
        self.logger.info(f"Running reconnaissance on {self.target}")
        
        # Perform passive reconnaissance
        self.passive_recon()
        
        # Perform active reconnaissance if not passive only
        if not passive_only:
            self.active_recon(skip_web=skip_web, use_ping_scan=use_ping_scan, 
                             use_netbios_scan=use_netbios_scan, 
                             use_aggressive_scan=use_aggressive_scan)
        
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
    
    def active_recon(self, skip_web=False, use_ping_scan=False, use_netbios_scan=False, use_aggressive_scan=False):
        """
        Perform active reconnaissance
        
        Args:
            skip_web (bool): Skip web scanning
            use_ping_scan (bool): Use Nmap ping scan for host discovery
            use_netbios_scan (bool): Use NetBIOS scan for host discovery
            use_aggressive_scan (bool): Use Nmap aggressive scan for port and service detection
        """
        self.logger.info("Starting active reconnaissance")
        
        # Initialize host discovery results
        if use_ping_scan or use_netbios_scan:
            self.results["active"]["host_discovery"] = {}
        
        # Perform host discovery scans if requested
        if use_ping_scan:
            ping_results = self.nmap_ping_scan()
            self.results["active"]["host_discovery"]["ping_scan"] = ping_results
            self.logger.info(f"Discovered {len(ping_results)} live hosts with ping scan")
        
        if use_netbios_scan:
            netbios_results = self.netbios_scan()
            self.results["active"]["host_discovery"]["netbios_scan"] = netbios_results
            self.logger.info(f"Discovered {len(netbios_results)} hosts with NetBIOS scan")
        
        # Perform aggressive scan if requested
        if use_aggressive_scan:
            aggressive_results = self.nmap_aggressive_scan()
            self.results["active"]["aggressive_scan"] = aggressive_results
            self.logger.info("Aggressive scan completed")
            
            # Extract port and service information from aggressive scan
            self.results["active"]["ports"] = aggressive_results.get("ports", {})
            self.results["active"]["services"] = aggressive_results.get("services", {})
            self.results["active"]["os_info"] = aggressive_results.get("os_info", {})
        else:
            # Use standard scans if aggressive scan not requested
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
    
    def nmap_ping_scan(self):
        """
        Perform Nmap ping scan for host discovery
        
        Returns:
            list: Live hosts discovered
        """
        self.logger.info(f"Performing Nmap ping scan on {self.target}")
        try:
            live_hosts = network.nmap_ping_scan(self.target)
            return live_hosts
        except Exception as e:
            self.logger.error(f"Error in Nmap ping scan: {str(e)}")
            return []
    
    def netbios_scan(self):
        """
        Perform NetBIOS scan for host discovery
        
        Returns:
            dict: NetBIOS information by host
        """
        self.logger.info(f"Performing NetBIOS scan on {self.target}")
        try:
            # Run the NetBIOS scan
            output = network.netbios_scan(self.target)
            
            # Parse the results using the dedicated parser
            if isinstance(output, str):
                netbios_info = parsers.parse_netbios_output(output)
                return netbios_info
            else:
                # If network.netbios_scan already returned parsed results
                return output
        except Exception as e:
            self.logger.error(f"Error in NetBIOS scan: {str(e)}")
            return {}
    
    def nmap_aggressive_scan(self):
        """
        Perform Nmap aggressive scan
        
        Returns:
            dict: Scan results including ports, services, and OS information
        """
        self.logger.info(f"Performing Nmap aggressive scan on {self.target}")
        try:
            # Run the aggressive scan
            output = network.nmap_aggressive_scan(self.target)
            
            # Parse the output
            if output:
                # Use the dedicated parser for aggressive scan output
                results = parsers.parse_nmap_aggressive_output(output)
                
                # Add the raw output for reference
                results["raw_output"] = output
                
                return results
            else:
                return {"error": "No output from aggressive scan"}
        except Exception as e:
            self.logger.error(f"Error in Nmap aggressive scan: {str(e)}")
            return {"error": str(e)}
    
    def port_scan(self):
        """
        Perform port scanning
        
        Returns:
            dict: Open ports and services
        """
        self.logger.info(f"Scanning ports on {self.target}")
        try:
            # Use nmap scanner from lib
            results = scanners.nmap_scan(self.target, scan_type="fast")
            return results
        except Exception as e:
            self.logger.error(f"Error in port scanning: {str(e)}")
            
            # Fallback to simple TCP port scan if nmap fails
            self.logger.info("Falling back to simple TCP port scan")
            results = {self.target: {"tcp": network.simple_port_scan(self.target)}}
            return results
    
    def service_enum(self):
        """
        Enumerate services on open ports
        
        Returns:
            dict: Service details
        """
        self.logger.info(f"Enumerating services on {self.target}")
        try:
            # Resolve domain to IP if needed
            target_ip = self.target
            if not network.is_ip_address(self.target):
                resolved_ip = network.resolve_domain(self.target)
                if resolved_ip:
                    target_ip = resolved_ip
            
            # Use nmap for service detection
            results = scanners.nmap_scan(target_ip, scan_type="service", ports="21,22,25,80,443,8080,8443")
            return results
        except Exception as e:
            self.logger.error(f"Error in service enumeration: {str(e)}")
            return {"error": str(e)}
    
    def vuln_scan(self):
        """
        Perform vulnerability scanning
        
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
            
            # Use nmap with vulnerability scripts
            results = scanners.nmap_scan(target_ip, scan_type="vuln", ports="21,22,25,80,443,8080,8443")
            
            # Extract vulnerabilities from results
            vulns = []
            for host_data in results.values():
                for proto_data in host_data.values():
                    for port_data in proto_data.values():
                        scripts = port_data.get("scripts", {})
                        for script_name, script_output in scripts.items():
                            if "VULNERABLE" in script_output:
                                vulns.append({
                                    "port": port_data.get("port", "unknown"),
                                    "service": port_data.get("service", "unknown"),
                                    "vulnerability": script_name,
                                    "details": script_output
                                })
            
            return {"vulnerabilities": vulns, "scan_data": results}
        except Exception as e:
            self.logger.error(f"Error in vulnerability scanning: {str(e)}")
            return {"error": str(e)}
    
    def web_scan(self):
        """
        Perform web scanning
        
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
            "interesting_files": []
        }
        
        for port in [80, 443, 8080, 8443]:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{self.target}:{port}"
            
            try:
                response = requests.get(url, timeout=10, verify=self.verify_ssl)
                
                results["headers"][f"{url}"] = dict(response.headers)
                
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
                
            except requests.exceptions.RequestException:
                continue
                
        return results
