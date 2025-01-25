import requests
import json
import time

def fetch_certificates(domain, retries=3, delay=10):
    """Fetch certificate transparency logs from crt.sh with retry logic."""
    try:
        crt_sh_url = f"https://crt.sh/?q={domain}&output=json"
        print(f"Fetching certificates for {domain} from crt.sh...")
        
        for attempt in range(retries):
            response = requests.get(crt_sh_url)
            
            if response.status_code == 429:
                print(f"Rate-limited by crt.sh. Retrying in {delay} seconds...")
                time.sleep(delay) 
                continue
            elif response.status_code == 200:
                return response.json() 
            else:
                print(f"Failed to fetch data from crt.sh. Status code: {response.status_code}")
                return None
        print("Max retries reached. Exiting.")
        return None
    except Exception as e:
        print(f"An error occurred while fetching data from crt.sh: {e}")
        return None

def parse_certificates(cert_data):
    """Parse the fetched certificate data and extract useful information."""
    cert_info = []
    try:
        for entry in cert_data:
            name_value = entry.get("name_value")
            issuer = entry.get("issuer_name")
            not_before = entry.get("not_before")
            not_after = entry.get("not_after")
            serial_number = entry.get("serial_number")
            signature_algorithm = entry.get("signature_algorithm")
            
            if name_value:
                domains = [name.strip() for name in name_value.split(",") if "CN=" not in name]
                
                cert_info.append({
                    "domains": domains,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "serial_number": serial_number,
                    "signature_algorithm": signature_algorithm
                })
        return cert_info
    except Exception as e:
        print(f"Error while parsing certificate data: {e}")
        return []

def save_certificates_to_file(domain, cert_info):
    """Save the extracted certificate information to a text file."""
    try:
        with open(f"{domain}_certificates_detailed.txt", "w") as file:
            if cert_info:
                file.write(f"=== Detailed Certificates for {domain} ===\n\n")
                for cert in cert_info:
                    file.write(f"Domains: {', '.join(cert['domains'])}\n")
                    file.write(f"Issuer: {cert['issuer']}\n")
                    file.write(f"Valid From: {cert['not_before']}\n")
                    file.write(f"Valid Until: {cert['not_after']}\n")
                    file.write(f"Serial Number: {cert['serial_number']}\n")
                    file.write(f"Signature Algorithm: {cert['signature_algorithm']}\n")
                    file.write("=" * 40 + "\n\n")
                print(f"Detailed certificates saved to {domain}_certificates_detailed.txt")
            else:
                file.write("No certificates found.\n")
                print("No certificates found.")
    except Exception as e:
        print(f"Error while saving certificates to file: {e}")

def run_cert_enum(domain):
    """Main function to fetch, parse, and save certificate data."""
    cert_data = fetch_certificates(domain)
    
    if cert_data:
        cert_info = parse_certificates(cert_data)
        
        save_certificates_to_file(domain, cert_info)
    else:
        print("No certificate data available to process.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 cert_enum_script.py <domain>")
    else:
        target_domain = sys.argv[1]
        run_cert_enum(target_domain)
