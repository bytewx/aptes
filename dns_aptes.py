import subprocess
import re

def parse_dig_output(output):
    answer_section = re.search(r";; ANSWER SECTION:\n((?:.+\n)+?)\n", output)
    return answer_section.group(1) if answer_section else "No ANSWER SECTION found."

def parse_nslookup_output(output):
    parsed = []
    for line in output.splitlines():
        if line.startswith("Name:") or line.startswith("Address:"):
            parsed.append(line)
    return "\n".join(parsed) if parsed else "No relevant information found."

def parse_whois_output(output):
    parsed = []
    for line in output.splitlines():
        if re.match(r"^(Registrar|Name Server):", line, re.IGNORECASE):
            parsed.append(line)
    return "\n".join(parsed) if parsed else "No relevant information found."

def run_dns_enum(domain):
    try:
        output_file = "dns_output.txt"

        output_data = []
        print(f"Starting DNS enumeration for domain: {domain}")

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for record_type in record_types:
            try:
                print(f"Running dig on domain: {domain} with {record_type} query...")
                dig_output = subprocess.check_output(["dig", domain, record_type], text=True)
                print(f"DIG Output for {record_type} captured successfully.")
                parsed_dig = parse_dig_output(dig_output)
                output_data.append(f"=== DIG Output ({record_type}) ===\n" + parsed_dig)
            except FileNotFoundError:
                output_data.append(f"dig is not installed or not found in PATH for {record_type} query.\n")
                print(f"Error: dig is not installed or not found in PATH for {record_type} query.")
            except subprocess.CalledProcessError as e:
                output_data.append(f"Error running dig for {record_type}: {e}\n")
                print(f"Error running dig for {record_type}: {e}")

        try:
            print(f"Running nslookup on domain: {domain}")
            nslookup_output = subprocess.check_output(["nslookup", domain], text=True)
            parsed_nslookup = parse_nslookup_output(nslookup_output)
            output_data.append("=== NSLOOKUP Output (Filtered) ===\n" + parsed_nslookup)
        except FileNotFoundError:
            output_data.append("nslookup is not installed or not found in PATH.\n")
            print("Error: nslookup is not installed or not found in PATH.")
        except subprocess.CalledProcessError as e:
            output_data.append(f"Error running nslookup: {e}\n")
            print(f"Error running nslookup: {e}")

        try:
            print(f"Running whois on domain: {domain}")
            whois_output = subprocess.check_output(["whois", domain], text=True)
            parsed_whois = parse_whois_output(whois_output)
            output_data.append("=== WHOIS Output (Filtered) ===\n" + parsed_whois)
        except FileNotFoundError:
            output_data.append("whois is not installed or not found in PATH.\n")
            print("Error: whois is not installed or not found in PATH.")
        except subprocess.CalledProcessError as e:
            output_data.append(f"Error running whois: {e}\n")
            print(f"Error running whois: {e}")

        with open(output_file, "w") as file:
            file.write("\n\n".join(output_data))

        print(f"Filtered DNS enumeration information saved to {output_file}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 dns_enum_script.py <domain>")
    else:
        target_domain = sys.argv[1]
        run_dns_enum(target_domain)
