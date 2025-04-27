#!/usr/bin/env python3
"""
Web analysis utilities for APTES
"""

import logging
import urllib.parse
import re

logger = logging.getLogger('aptes.webanalysis')

# Check for optional imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

def analyze_web_service(host, port, url, verify_ssl=False):
    """
    Analyze a web service for vulnerabilities
    
    Args:
        host (str): Target host
        port (str): Target port
        url (str): URL to analyze
        verify_ssl (bool): Verify SSL certificates
    
    Returns:
        dict: Analysis results
    """
    if not REQUESTS_AVAILABLE:
        logger.error("Requests library not available, skipping web analysis")
        return None
    
    logger.debug(f"Analyzing web application at {url}")
    
    findings = []
    service_info = {
        "url": url,
        "host": host,
        "port": port,
        "headers": {},
        "technologies": [],
        "server": "",
        "status_code": 0
    }
    
    try:
        # Request the main page
        response = requests.get(url, timeout=10, verify=verify_ssl, allow_redirects=True)
        service_info["status_code"] = response.status_code
        service_info["headers"] = dict(response.headers)
        service_info["final_url"] = response.url
        
        # Extract server information
        if "Server" in response.headers:
            service_info["server"] = response.headers["Server"]
        
        # Check for missing security headers
        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]
        
        for header in security_headers:
            if header not in response.headers:
                findings.append({
                    "host": host,
                    "port": port,
                    "url": url,
                    "category": "Missing Security Headers",
                    "finding": f"Missing {header} header",
                    "risk_level": "low",
                    "description": f"The {header} security header is missing from the response.",
                    "recommendation": f"Implement the {header} header to enhance security."
                })
        
        # Check for directory listing
        common_dirs = ["backup", "admin", "wp-admin", "config", "test", "dev"]
        for directory in common_dirs:
            try:
                dir_url = f"{url}/{directory}/"
                dir_response = requests.get(dir_url, timeout=5, verify=verify_ssl)
                
                if dir_response.status_code == 200:
                    listing_patterns = [
                        "Index of /",
                        "Directory Listing For",
                        "<title>Index of",
                        "Parent Directory</a>"
                    ]
                    
                    for pattern in listing_patterns:
                        if pattern in dir_response.text:
                            findings.append({
                                "host": host,
                                "port": port,
                                "url": dir_url,
                                "category": "Directory Listing",
                                "finding": f"Directory listing enabled at {directory}/",
                                "risk_level": "medium",
                                "description": "The web server is configured to show directory listings, which can expose sensitive files.",
                                "recommendation": "Disable directory listings in the web server configuration."
                            })
                            break
            except Exception:
                pass
        
        # Test for common web vulnerabilities
        test_web_vulnerabilities(url, host, port, findings, verify_ssl)
        
    except Exception as e:
        logger.debug(f"Error analyzing {url}: {str(e)}")
    
    return {
        "service": service_info,
        "findings": findings
    }

def test_web_vulnerabilities(url, host, port, findings, verify_ssl=False):
    """
    Test for common web vulnerabilities
    
    Args:
        url (str): Base URL to test
        host (str): Target host
        port (str): Target port
        findings (list): List to append findings to
        verify_ssl (bool): Verify SSL certificates
    """
    if not REQUESTS_AVAILABLE:
        return
    
    # Test for SQL injection
    sql_paths = ["/login", "/search", "/product", "/user"]
    sql_payloads = ["'", "' OR '1'='1", "1' OR '1'='1"]
    
    for path in sql_paths:
        for payload in sql_payloads:
            try:
                test_url = f"{url}{path}?id={urllib.parse.quote_plus(payload)}"
                response = requests.get(test_url, timeout=5, verify=verify_ssl)
                
                # Look for SQL error messages
                sql_errors = [
                    "sql syntax",
                    "syntax error",
                    "mysql_fetch",
                    "unclosed quotation mark",
                    "ORA-",
                    "pg_query"
                ]
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        findings.append({
                            "host": host,
                            "port": port,
                            "url": test_url,
                            "category": "SQL Injection",
                            "finding": f"Potential SQL injection vulnerability at {path}",
                            "risk_level": "high",
                            "description": "The application may be vulnerable to SQL injection attacks. SQL error messages were detected in the response.",
                            "recommendation": "Implement proper input validation and parameterized queries."
                        })
                        break
            except Exception:
                pass
    
    # Test for XSS
    xss_paths = ["/search", "/comment", "/feedback"]
    xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    
    for path in xss_paths:
        for payload in xss_payloads:
            try:
                test_url = f"{url}{path}?q={urllib.parse.quote_plus(payload)}"
                response = requests.get(test_url, timeout=5, verify=verify_ssl)
                
                # Check if payload is reflected
                if payload in response.text:
                    findings.append({
                        "host": host,
                        "port": port,
                        "url": test_url,
                        "category": "Cross-Site Scripting (XSS)",
                        "finding": f"Potential XSS vulnerability at {path}",
                        "risk_level": "medium",
                        "description": "The application may be vulnerable to Cross-Site Scripting attacks. User input is being reflected in the response without proper sanitization.",
                        "recommendation": "Implement proper output encoding and content security policy."
                    })
                    break
            except Exception:
                pass
    
    # Test for local file inclusion
    lfi_paths = ["/include", "/file", "/page", "/view"]
    lfi_payloads = ["../../../etc/passwd", "../../../windows/win.ini", "..%2f..%2f..%2fetc%2fpasswd"]
    
    for path in lfi_paths:
        for payload in lfi_payloads:
            try:
                test_url = f"{url}{path}?file={urllib.parse.quote_plus(payload)}"
                response = requests.get(test_url, timeout=5, verify=verify_ssl)
                
                # Check for LFI indicators
                lfi_patterns = [
                    "root:x:",
                    "[fonts]",
                    "bin/bash",
                    "for 16-bit app support"
                ]
                
                for pattern in lfi_patterns:
                    if pattern in response.text:
                        findings.append({
                            "host": host,
                            "port": port,
                            "url": test_url,
                            "category": "Local File Inclusion",
                            "finding": f"Potential LFI vulnerability at {path}",
                            "risk_level": "high",
                            "description": "The application may be vulnerable to Local File Inclusion attacks. Server files can be accessed through path traversal.",
                            "recommendation": "Validate and sanitize file paths, use whitelists of allowed files."
                        })
                        break
            except Exception:
                pass

def detect_web_technologies(headers, body):
    """
    Detect web technologies from headers and body
    
    Args:
        headers (dict): HTTP headers
        body (str): Response body
    
    Returns:
        dict: Detected technologies
    """
    technologies = {
        "server": None,
        "framework": None,
        "cms": None,
        "javascript": []
    }
    
    # Check headers for server info
    if "Server" in headers:
        technologies["server"] = headers["Server"]
    
    if "X-Powered-By" in headers:
        if "PHP" in headers["X-Powered-By"]:
            technologies["framework"] = f"PHP {headers['X-Powered-By'].split('/')[1]}" if "/" in headers["X-Powered-By"] else "PHP"
        elif "ASP.NET" in headers["X-Powered-By"]:
            technologies["framework"] = headers["X-Powered-By"]
    
    # Check for common CMS indicators in body
    if body:
        # WordPress
        if re.search(r'wp-content|wordpress|wp-includes', body, re.I):
            technologies["cms"] = "WordPress"
            # Try to get version
            wp_version = re.search(r'meta name="generator" content="WordPress ([0-9.]+)', body)
            if wp_version:
                technologies["cms"] = f"WordPress {wp_version.group(1)}"
        
        # Joomla
        elif re.search(r'joomla|com_content|com_contact', body, re.I):
            technologies["cms"] = "Joomla"
        
        # Drupal
        elif re.search(r'drupal|sites/all|drupal.org', body, re.I):
            technologies["cms"] = "Drupal"
        
        # JavaScript frameworks
        js_frameworks = {
            "jquery": r'jquery(?:\.min)?\.js',
            "react": r'react(?:\.min)?\.js|reactjs',
            "angular": r'angular(?:\.min)?\.js|angularjs',
            "vue": r'vue(?:\.min)?\.js|vuejs',
            "bootstrap": r'bootstrap(?:\.min)?\.js'
        }
        
        for framework, pattern in js_frameworks.items():
            if re.search(pattern, body, re.I):
                technologies["javascript"].append(framework)
    
    return technologies