#!/usr/bin/env python3
"""
Vulnerability validation utilities for APTES
"""

import re
import logging
import subprocess

logger = logging.getLogger('aptes.validators')

# Check for optional imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

def validate_vulnerability(target, vuln, verify_ssl=True):
    """
    Validate and enhance a vulnerability
    
    Args:
        target (str): Target host
        vuln (dict): Vulnerability information
        verify_ssl (bool): Verify SSL certificates
    
    Returns:
        dict: Enhanced vulnerability information
    """
    port = vuln.get("port", "unknown")
    service = vuln.get("service", "unknown")
    vuln_name = vuln.get("vulnerability", "unknown")
    
    logger.debug(f"Validating {vuln_name} on {target}:{port} ({service})")
    
    # Enhance the vulnerability data
    enhanced_vuln = vuln.copy()
    enhanced_vuln["host"] = target
    enhanced_vuln["validated"] = False
    enhanced_vuln["validation_method"] = "manual"
    enhanced_vuln["risk_level"] = vuln.get("risk_level", "medium")  # Default
    
    # Add CVE details if present in the vulnerability name
    cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', vuln_name)
    if cve_match:
        enhanced_vuln["cve"] = cve_match.group(1)
        
        # Try to get CVE details
        try:
            if REQUESTS_AVAILABLE:
                cve_id = enhanced_vuln["cve"]
                response = requests.get(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}", 
                                       timeout=10, verify=verify_ssl)
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data and "CVE_Items" in data["result"] and data["result"]["CVE_Items"]:
                        cve_data = data["result"]["CVE_Items"][0]
                        
                        # Extract CVSS score and severity
                        if "impact" in cve_data:
                            if "baseMetricV3" in cve_data["impact"]:
                                enhanced_vuln["cvss_v3"] = cve_data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                                enhanced_vuln["risk_level"] = cve_data["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"].lower()
                            elif "baseMetricV2" in cve_data["impact"]:
                                enhanced_vuln["cvss_v2"] = cve_data["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                                
                                # Map CVSS V2 score to risk level
                                score = float(enhanced_vuln["cvss_v2"])
                                if score >= 9.0:
                                    enhanced_vuln["risk_level"] = "critical"
                                elif score >= 7.0:
                                    enhanced_vuln["risk_level"] = "high"
                                elif score >= 4.0:
                                    enhanced_vuln["risk_level"] = "medium"
                                else:
                                    enhanced_vuln["risk_level"] = "low"
        except Exception as e:
            logger.debug(f"Error fetching CVE details: {str(e)}")
    
    # Attempt validation based on service type
    if "http" in service or port in ["80", "443", "8080", "8443"]:
        validated = validate_web_vulnerability(enhanced_vuln, verify_ssl)
        enhanced_vuln["validated"] = validated
        enhanced_vuln["validation_method"] = "web_request"
    elif "ssh" in service:
        enhanced_vuln["validation_method"] = "ssh_check"
    elif "ftp" in service:
        enhanced_vuln["validation_method"] = "ftp_check"
    
    return enhanced_vuln

def validate_web_vulnerability(vuln, verify_ssl=True):
    """
    Validate a web vulnerability
    
    Args:
        vuln (dict): Vulnerability information
        verify_ssl (bool): Verify SSL certificates
    
    Returns:
        bool: True if validated, False otherwise
    """
    if not REQUESTS_AVAILABLE:
        logger.debug("Cannot validate web vulnerability: requests library not available")
        return False
    
    host = vuln.get("host", "")
    port = vuln.get("port", "80")
    protocol = "https" if port in ["443", "8443"] else "http"
    url = f"{protocol}://{host}:{port}"
    
    vuln_name = vuln.get("vulnerability", "").lower()
    
    # Validation is limited without actual exploitation
    # In a real implementation, would perform more detailed checks
    try:
        # Basic check: can we connect to the service?
        response = requests.get(url, timeout=5, verify=verify_ssl)
        
        # Check for potential SQL injection vulnerabilities
        if "sql injection" in vuln_name:
            test_url = f"{url}/search?q=%27+OR+1%3D1--"
            try:
                test_response = requests.get(test_url, timeout=5, verify=verify_ssl)
                if any(err in test_response.text.lower() for err in [
                    "sql syntax", "mysql_fetch", "oci_", "oracle", "pg_", "unclosed quotation"
                ]):
                    return True
            except:
                pass
        
        # Check for potential XSS vulnerabilities
        elif "xss" in vuln_name or "cross-site scripting" in vuln_name:
            test_url = f"{url}/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
            try:
                test_response = requests.get(test_url, timeout=5, verify=verify_ssl)
                if "<script>alert(1)</script>" in test_response.text:
                    return True
            except:
                pass
        
        # Check for potential file inclusion vulnerabilities
        elif "file inclusion" in vuln_name or "lfi" in vuln_name or "rfi" in vuln_name:
            test_url = f"{url}/index.php?page=../../../etc/passwd"
            try:
                test_response = requests.get(test_url, timeout=5, verify=verify_ssl)
                if "root:" in test_response.text and "bash" in test_response.text:
                    return True
            except:
                pass
    
    except Exception as e:
        logger.debug(f"Error validating web vulnerability: {str(e)}")
    
    return False

def check_known_vulnerabilities(host, port, service, product, version):
    """
    Check for known vulnerabilities in services
    
    Args:
        host (str): Target host
        port (str): Target port
        service (str): Service type
        product (str): Product name
        version (str): Version string
    
    Returns:
        list: Potential vulnerabilities
    """
    vulnerabilities = []
    
    # Database of known vulnerabilities
    vuln_db = {
        "apache": {
            "2.4.49": {
                "cve": "CVE-2021-41773",
                "name": "Apache HTTP Server Path Traversal",
                "risk_level": "critical"
            },
            "2.4.50": {
                "cve": "CVE-2021-42013",
                "name": "Apache HTTP Server Path Traversal",
                "risk_level": "critical"
            }
        },
        "nginx": {
            "1.3.9": {
                "cve": "CVE-2013-4547",
                "name": "NGINX HTTP URI Processing Security Bypass",
                "risk_level": "high"
            }
        },
        "openssh": {
            "7.7": {
                "cve": "CVE-2018-15473",
                "name": "OpenSSH Username Enumeration",
                "risk_level": "medium"
            }
        }
    }
    
    # Generic vulnerabilities by service type
    generic_vulns = {
        "http": [
            {
                "name": "Potential SQL Injection",
                "risk_level": "high",
                "description": "Web applications may be vulnerable to SQL injection if user input is not properly sanitized."
            },
            {
                "name": "Potential Cross-Site Scripting (XSS)",
                "risk_level": "medium",
                "description": "Web applications may be vulnerable to XSS if user input is not properly sanitized."
            }
        ],
        "ftp": [
            {
                "name": "Anonymous FTP Access",
                "risk_level": "medium",
                "description": "FTP server may allow anonymous access, exposing files to unauthorized users."
            }
        ],
        "ssh": [
            {
                "name": "Weak SSH Configurations",
                "risk_level": "medium",
                "description": "SSH server may have weak ciphers or authentication methods enabled."
            }
        ]
    }
    
    # Check product-specific vulnerabilities
    for db_product, versions in vuln_db.items():
        if db_product in product.lower():
            for vuln_version, vuln_info in versions.items():
                if version.startswith(vuln_version):
                    vulnerabilities.append({
                        "host": host,
                        "port": port,
                        "service": service,
                        "product": product,
                        "version": version,
                        "vulnerability": vuln_info["name"],
                        "cve": vuln_info["cve"],
                        "risk_level": vuln_info["risk_level"],
                        "validated": False,
                        "validation_method": "version_check"
                    })
    
    # Add generic service vulnerabilities
    for db_service, vulns in generic_vulns.items():
        if db_service in service.lower():
            for vuln in vulns:
                vulnerabilities.append({
                    "host": host,
                    "port": port,
                    "service": service,
                    "vulnerability": vuln["name"],
                    "risk_level": vuln["risk_level"],
                    "description": vuln["description"],
                    "validated": False,
                    "validation_method": "service_check"
                })
    
    return vulnerabilities

def test_service_credentials(service):
    """
    Test credentials for a specific service
    
    Args:
        service (dict): Service information
    
    Returns:
        dict: Test results
    """
    host = service["host"]
    port = service["port"]
    service_name = service["service"]
    
    logger.debug(f"Testing credentials for {service_name} on {host}:{port}")
    
    findings = []
    
    # Service-specific credential testing
    if service_name in ["http", "https"]:
        findings.extend(test_web_credentials(host, port, service_name))
    elif service_name == "ftp":
        findings.extend(test_ftp_credentials(host, port))
    elif service_name == "ssh":
        findings.extend(test_ssh_credentials(host, port))
    
    return {
        "service": {
            "host": host,
            "port": port,
            "name": service_name
        },
        "findings": findings
    }

def test_web_credentials(host, port, service):
    """
    Test credentials for web services
    
    Args:
        host (str): Target host
        port (str): Target port
        service (str): Service type
    
    Returns:
        list: Findings
    """
    if not REQUESTS_AVAILABLE:
        return []
    
    findings = []
    protocol = "https" if service == "https" or port in ["443", "8443"] else "http"
    
    # Common admin paths
    admin_paths = [
        "/admin",
        "/administrator",
        "/login",
        "/wp-admin",
        "/admin-panel"
    ]
    
    # Default credentials to test
    default_creds = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "administrator", "password": "administrator"},
        {"username": "root", "password": "root"}
    ]
    
    # Check each admin path
    for path in admin_paths:
        url = f"{protocol}://{host}:{port}{path}"
        
        try:
            # First check if the page exists
            response = requests.get(url, timeout=5, verify=False)
            
            # Look for login forms
            if response.status_code == 200 and ("login" in response.text.lower() or "password" in response.text.lower()):
                logger.debug(f"Found potential login page at {url}")
                
                # In a real implementation, would attempt logins
                # Here we'll just report it as a finding to check manually
                findings.append({
                    "host": host,
                    "port": port,
                    "service": service,
                    "finding": f"Potential login page found at {url}",
                    "category": "Default Credentials",
                    "risk_level": "info",
                    "description": "A login page was identified which should be checked for default or weak credentials.",
                    "credentials_to_try": [f"{cred['username']}:{cred['password']}" for cred in default_creds[:3]],
                    "recommendation": "Try default credentials and ensure strong password policies are enforced."
                })
        except Exception:
            pass
    
    return findings

def test_ftp_credentials(host, port):
    """
    Test credentials for FTP services
    
    Args:
        host (str): Target host
        port (str): Target port
    
    Returns:
        list: Findings
    """
    findings = []
    
    # Try anonymous access
    try:
        cmd = f"timeout 10 ftp -n {host} {port} <<EOF\nuser anonymous anonymous\nls\nquit\nEOF"
        output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
        
        if "230" in output:  # 230 = Login successful
            findings.append({
                "host": host,
                "port": port,
                "service": "ftp",
                "finding": "Anonymous FTP access allowed",
                "category": "Default Credentials",
                "risk_level": "medium",
                "description": "The FTP server allows anonymous access, which could expose sensitive files.",
                "credentials": "anonymous:anonymous",
                "recommendation": "Disable anonymous FTP access unless specifically required."
            })
    except Exception:
        pass
    
    return findings

def test_ssh_credentials(host, port):
    """
    Test credentials for SSH services
    
    Args:
        host (str): Target host
        port (str): Target port
    
    Returns:
        list: Findings
    """
    # In a real implementation, would attempt common credentials
    # Here we'll just return a suggestion to check manually
    
    findings = [{
        "host": host,
        "port": port,
        "service": "ssh",
        "finding": "SSH service should be checked for default credentials",
        "category": "Default Credentials",
        "risk_level": "info",
        "description": "The SSH service should be manually checked for default or weak credentials.",
        "credentials_to_try": ["root:root", "admin:admin", "user:password"],
        "recommendation": "Ensure strong password policies and consider using key-based authentication instead of passwords."
    }]
    
    return findings 