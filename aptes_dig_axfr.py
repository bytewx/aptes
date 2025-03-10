import subprocess
import re

def run_nmap(target):
    try:
        flags = ["-Pn", "-sC", "-sV"]
        command = ["nmap"] + flags + [target]
        print(f"Running nmap: {' '.join(command)}")
        nmap_output = subprocess.check_output(command, text=True)

        domain_service_ip = None
        port_info = []

        for line in nmap_output.splitlines():
            if re.match(r"^\d+/[a-z]+\s+", line): 
                port_info.append(line)
                if "domain" in line.lower():
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        domain_service_ip = match.group(1)

        with open("output.txt", "w") as file:
            file.write("\n".join(port_info))

        print("\n".join(port_info))
        print(f"Port information saved to output.txt")

        return domain_service_ip

    except subprocess.CalledProcessError as e:
        print(f"Error running nmap: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

    return None

def run_dig_axfr(domain_ip):
    try:
        if domain_ip:
            print(f"Running dig AXFR against {domain_ip}")
            dig_output = subprocess.check_output(["dig", "axfr", domain_ip], text=True)

            with open("dig_output.txt", "w") as file:
                file.write(dig_output)

            print("Zone Transfer Output:\n", dig_output)
            print(f"Zone transfer saved to dig_output.txt")
        else:
            print("No domain service found. Skipping dig AXFR.")

    except subprocess.CalledProcessError as e:
        print(f"Error running dig: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <target>")
    else:
        target_ip_or_domain = sys.argv[1]
        domain_ip = run_nmap(target_ip_or_domain)
        run_dig_axfr(domain_ip)
