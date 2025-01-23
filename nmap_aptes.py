import subprocess
import re

def run_nmap(target):
    try:
        flags = ["-Pn", "-sC", "-sV"]
        output_file = "output.txt"

        command = ["nmap"] + flags + [target]
        print(f"Running nmap: {' '.join(command)}")
        nmap_output = subprocess.check_output(command, text=True)
        
        port_info = []
        capture = False
        for line in nmap_output.splitlines():
            if line.startswith("PORT"):
                capture = True
            if capture:
                if re.match(r"^\d+/[a-z]+\s+", line):
                    port_info.append(line)
                elif not line.strip():
                    break

        with open(output_file, "w") as file:
            file.write("\n".join(port_info))

        for line in port_info.splitlines():
            print(line)

        print(f"Port information saved to {output_file}")

    except subprocess.CalledProcessError as e:
        print(f"Error running nmap: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <target>")
    else:
        target_ip_or_domain = sys.argv[1]
        run_nmap(target_ip_or_domain)
