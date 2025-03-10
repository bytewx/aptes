import subprocess
import re
import json
import sys
import requests

def run_nmap(target):
    try:
        flags = ["-Pn", "-sC", "-sV"]
        command = ["nmap"] + flags + [target]
        print(f"Running nmap: {' '.join(command)}")
        nmap_output = subprocess.check_output(command, text=True)

        service_versions = {}
        for line in nmap_output.splitlines():
            match = re.match(r"^(\d+/[a-z]+)\s+open\s+([^ ]+)\s+(.*)$", line)
            if match:
                port, service, version = match.groups()
                service_versions[service] = version.strip()

        with open("nmap_output.json", "w") as file:
            json.dump(service_versions, file, indent=4)

        print(json.dumps(service_versions, indent=4))
        return service_versions
    
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return {}

def check_cve(service_versions):
    cve_results = {}
    cve_api = "https://services.nvd.nist.gov/rest/json/cves/2.0" 
    
    for service, version in service_versions.items():
        try:
            query = f"{service} {version}"
            response = requests.get(cve_api, params={"keywordSearch": query, "resultsPerPage": 5})
            if response.status_code == 200:
                cve_data = response.json()
                cve_entries = cve_data.get("vulnerabilities", [])
                cve_results[service] = [entry["cve"]["id"] for entry in cve_entries]
            else:
                print(f"Failed to fetch CVE data for {service} {version}")
        except Exception as e:
            print(f"Error checking CVE for {service} {version}: {e}")

    with open("cve_results.txt", "w") as file:
        for service, cves in cve_results.items():
            file.write(f"{service} ({service_versions[service]}):\n")
            file.write("\n".join(cves) + "\n\n")
    
    print("CVE results saved to cve_results.txt")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    service_versions = run_nmap(target)
    if service_versions:
        check_cve(service_versions)

if __name__ == "__main__":
    main()
