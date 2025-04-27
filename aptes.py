#!/usr/bin/env python3
"""
APTES - Advanced Penetration Testing and Exploitation Suite
----------------------------------------------------------
A comprehensive security assessment framework for reconnaissance,
pre-exploitation, exploitation, and post-exploitation phases.

Usage: python aptes.py [target] [options]
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Import APTES modules
from config import Config
from utils.logger import setup_logger
from phases.recon import ReconnaissancePhase
from phases.preexploit import PreExploitationPhase
from phases.exploit import ExploitationPhase
from phases.postexploit import PostExploitationPhase

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description='APTES - Advanced Penetration Testing and Exploitation Suite')
    
    # Target argument
    parser.add_argument('target', nargs='?', help='Target host or IP address')
    
    # Phase selection
    parser.add_argument('-p', '--phase', choices=['recon', 'preexploit', 'exploit', 'postexploit', 'all'],
                        default='preexploit', help='Phase to run (default: preexploit)')
    
    # General options
    parser.add_argument('-o', '--output-dir', default='reports',
                        help='Directory for output reports (default: reports)')
    
    parser.add_argument('-r', '--results-file',
                        help='Load results from previous phase')
    
    parser.add_argument('--threads', type=int, default=3,
                        help='Number of threads for concurrent operations (default: 3)')
    
    parser.add_argument('--format', choices=['json', 'excel', 'md', 'all'], default='all',
                        help='Report format (default: all)')
    
    # Reconnaissance phase options
    parser.add_argument('--passive-only', action='store_true',
                        help='Perform only passive reconnaissance')
    
    parser.add_argument('--skip-web', action='store_true',
                        help='Skip web scanning during recon')
    
    # New host discovery options
    parser.add_argument('--ping-scan', action='store_true',
                        help='Use Nmap ping scan for host discovery')
    
    parser.add_argument('--netbios-scan', action='store_true',
                        help='Use NetBIOS scan for host discovery')
    
    # New port scanning options
    parser.add_argument('--aggressive-scan', action='store_true',
                        help='Use Nmap aggressive scan (-T4 -A -v) for port and service detection')
    
    # Pre-exploitation phase options
    parser.add_argument('--filter', choices=['all', 'critical', 'high', 'medium', 'low'],
                        default='all', help='Risk level filter (default: all)')
    
    parser.add_argument('--no-creds', action='store_true',
                        help='Skip default credential testing')
    
    parser.add_argument('--no-payloads', action='store_true',
                        help='Skip payload generation')
    
    # Exploitation phase options
    parser.add_argument('--auto-exploit', action='store_true',
                        help='Automatically exploit without confirmation')
    
    # Post-exploitation phase options
    parser.add_argument('--install-persistence', action='store_true',
                        help='Install persistence mechanisms')
    
    parser.add_argument('--exfiltrate-data', action='store_true',
                        help='Exfiltrate sensitive data')
    
    parser.add_argument('--no-cleanup', action='store_true',
                        help='Skip cleaning up traces of activity')
    
    # Verbosity options
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress all output except errors')
    
    parser.add_argument('--no-verify-ssl', action='store_true',
                    help='Disable SSL certificate verification (security risk)')
    
    parser.add_argument('--suppress-ssl-warnings', action='store_true', default=True,
                        help='Suppress SSL certificate warnings')
    
    args = parser.parse_args()
    
    # Handle custom help flag
    if len(sys.argv) == 1:
        print_usage()
        sys.exit(1)
        
    return args

def print_usage():
    """Print usage information for APTES"""
    print("\nAPTES - Advanced Penetration Testing and Exploitation Suite")
    print("\nUsage: python -m aptes [TARGET] [OPTIONS]")
    print("\nError: No target specified. Please provide a target to scan.")
    
    print("\nBasic Usage:")
    print("  python -m aptes <target> [options]")
    print("\nExamples:")
    print("  python -m aptes example.com                # Run pre-exploitation phase against example.com")
    print("  python -m aptes 192.168.1.10 -p recon      # Run only reconnaissance phase")
    print("  python -m aptes target.org --filter high   # Focus on high-risk vulnerabilities")
    print("  python -m aptes 192.168.1.0/24 --ping-scan # Perform host discovery with Nmap ping scan")
    print("  python -m aptes 192.168.1.10 --aggressive-scan # Run aggressive port and service scan")
    
    print("\nOptions:")
    print("  Target Selection:")
    print("    TARGET                  Target host or IP address to assess")
    print("\n  Phase Selection:")
    print("    -p, --phase {recon,preexploit,exploit,postexploit,all}")
    print("                            Phase to run (default: preexploit)")
    
    print("\n  General Options:")
    print("    -o, --output-dir DIR    Directory for output reports (default: reports)")
    print("    -r, --results-file FILE Load results from previous phase")
    print("    --threads N             Number of threads for concurrent operations (default: 3)")
    print("    --format {json,excel,md,all}")
    print("                            Report format (default: all)")
    
    print("\n  Reconnaissance Options:")
    print("    --passive-only          Perform only passive reconnaissance")
    print("    --skip-web              Skip web scanning")
    print("    --ping-scan             Use Nmap ping scan for host discovery")
    print("    --netbios-scan          Use NetBIOS scan for host discovery")
    print("    --aggressive-scan       Use Nmap aggressive scan for port and service detection")
    
    print("\n  Verbosity Options:")
    print("    -v, --verbose           Enable verbose output")
    print("    -q, --quiet             Suppress all output except errors")
    
    print("\nFor full documentation, visit: https://github.com/byteshell/aptes")

class APTESFramework:
    """Main APTES Framework Class"""
    
    def __init__(self, target=None, output_dir="reports", threads=3, verbosity=1, verify_ssl=True):
        """Initialize the APTES framework"""
        self.target = target
        self.output_dir = output_dir
        self.threads = threads
        self.verbosity = verbosity
        self.verify_ssl = verify_ssl
        
        # Setup logging
        self.logger = setup_logger('aptes', verbosity)
        
        # Configure SSL warnings
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Initialize configuration
        self.config = Config(target, output_dir, threads, verbosity, verify_ssl)
        self.results = self.config.results
        
        # Initialize phase controllers with proper reference to framework
        self.recon = ReconnaissancePhase(self)
        self.preexploit = PreExploitationPhase(self)
        self.exploit = ExploitationPhase(self)
        self.postexploit = PostExploitationPhase(self)
        
        # Current phase tracking
        self.current_phase = None
    
    def run_phase(self, phase_name, **kwargs):
        """Run a specific phase of the framework"""
        if phase_name not in ["recon", "preexploit", "exploit", "postexploit"]:
            self.logger.error(f"Unknown phase: {phase_name}")
            return False
        
        self.current_phase = phase_name
        self.logger.info(f"Starting {phase_name} phase for {self.target}")
        
        start_time = datetime.now()
        phase_controller = getattr(self, phase_name)
        
        # Run the phase
        try:
            # Run the phase and get results
            result = phase_controller.run(**kwargs)
            
            # Store results in the framework's results dictionary
            self.results[phase_name] = result
            
            # Calculate duration
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            self.results[phase_name]["duration"] = duration
            
            self.logger.info(f"{phase_name.capitalize()} phase completed in {duration:.2f} seconds")
            return True
        except Exception as e:
            self.logger.error(f"Error in {phase_name} phase: {str(e)}")
            if self.verbosity >= 2:
                import traceback
                traceback.print_exc()
            return False
    
    def save_results(self, filename=None):
        """Save all results to a JSON file"""
        return self.config.save_results(filename)
    
    def load_results(self, filename):
        """Load results from a JSON file"""
        return self.config.load_results(filename)
    
    def print_banner(self):
        """Print the APTES banner"""
        banner = """
        ╔═══════════════════════════════════════════════════════╗
        ║             APTES - Advanced Penetration              ║
        ║             Testing and Exploitation Suite            ║
        ╚═══════════════════════════════════════════════════════╝
        """
        print(banner)
        print(f"  Target: {self.target}")
        print(f"  Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("  " + "="*53)

def print_summary(framework, phase):
    """Print a summary of results from a phase"""
    # Safely get results for the phase
    results = {}
    try:
        results = framework.results.get(phase, {})
    except (AttributeError, KeyError):
        print(f"\nNo results available for {phase} phase")
        return
    
    if not results:
        print(f"\nNo results available for {phase} phase")
        return
    
    print(f"\n{'=' * 50}")
    print(f"{phase.upper()} PHASE SUMMARY")
    print(f"{'=' * 50}\n")
    
    if phase == "recon":
        # Print reconnaissance summary
        if "passive" in results:
            print("Passive Reconnaissance:")
            if "dns" in results["passive"]:
                print(f"  - DNS Records: {sum(len(records) for records in results['passive']['dns'].values())} entries found")
            if "subdomains" in results["passive"]:
                print(f"  - Subdomains: {len(results['passive']['subdomains'])} discovered")
            if "ssl_info" in results["passive"]:
                print(f"  - SSL Information: {'Collected' if results['passive']['ssl_info'] else 'None'}")
        
        if "active" in results:
            print("\nActive Reconnaissance:")
            
            # Host discovery
            if "host_discovery" in results["active"]:
                if "ping_scan" in results["active"]["host_discovery"]:
                    print(f"  - Ping Scan: {len(results['active']['host_discovery']['ping_scan'])} live hosts discovered")
                if "netbios_scan" in results["active"]["host_discovery"]:
                    print(f"  - NetBIOS Scan: {len(results['active']['host_discovery']['netbios_scan'])} hosts with NetBIOS info")
            
            # Port scan
            if "ports" in results["active"]:
                open_ports = 0
                for host_data in results["active"]["ports"].values():
                    for proto_data in host_data.values():
                        open_ports += len(proto_data)
                print(f"  - Open Ports: {open_ports} discovered")
            
            # Aggressive scan results
            if "aggressive_scan" in results["active"]:
                print(f"  - Aggressive Scan: Completed")
                if "os_info" in results["active"] and "details" in results["active"]["os_info"]:
                    print(f"  - OS Detection: {results['active']['os_info']['details']}")
            
            # Services
            if "services" in results["active"]:
                services = set()
                for host_data in results["active"]["services"].values():
                    for proto_data in host_data.values():
                        for port_data in proto_data.values():
                            services.add(port_data.get("service", "unknown"))
                print(f"  - Services: {', '.join(services) if services else 'None identified'}")
            
            # Vulnerabilities
            if "vulnerabilities" in results["active"]:
                vulns = results["active"]["vulnerabilities"].get("vulnerabilities", [])
                print(f"  - Potential Vulnerabilities: {len(vulns)} found")
            
            # Web
            if "web" in results["active"]:
                web_results = results["active"]["web"]
                print(f"  - Web Technologies: {', '.join(web_results.get('technologies', [])) if web_results.get('technologies') else 'None identified'}")
    
    elif phase == "preexploit":
        # Print pre-exploitation summary
        if "vulnerability_validation" in results:
            vuln_count = results["vulnerability_validation"].get("total_count", 0)
            print(f"Validated Vulnerabilities: {vuln_count}")
            
            # Count by risk level
            risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for vuln in results["vulnerability_validation"].get("vulnerabilities", []):
                risk = vuln.get("risk_level", "info").lower()
                if risk in risk_levels:
                    risk_levels[risk] += 1
            
            for risk, count in risk_levels.items():
                if count > 0:
                    print(f"  - {risk.capitalize()}: {count}")
        
        if "webapp_analysis" in results:
            web_count = results["webapp_analysis"].get("total_findings", 0)
            print(f"\nWeb Application Findings: {web_count}")
            
            # Categories
            if "grouped_findings" in results["webapp_analysis"]:
                for category, findings in results["webapp_analysis"]["grouped_findings"].items():
                    print(f"  - {category}: {len(findings)}")
        
        if "attack_vectors" in results:
            attack_count = len(results["attack_vectors"])
            print(f"\nIdentified Attack Vectors: {attack_count}")
            
            # Show top 3 attack vectors
            top_vectors = sorted([v for v in results["attack_vectors"] 
                               if v.get("risk_level") in ["critical", "high"]], 
                              key=lambda x: {"critical": 0, "high": 1}.get(x.get("risk_level"), 2))[:3]
            
            if top_vectors:
                print(f"\nTop attack vectors:")
                for i, vector in enumerate(top_vectors, 1):
                    print(f"  {i}. [{vector.get('risk_level', '').upper()}] {vector.get('name', 'Unknown')}")
    
    elif phase == "exploit":
        # Print exploitation summary
        print("Exploitation Summary:")
        print(f"  - Attempts: {results['exploitation_summary'].get('attempts', 0)}")
        print(f"  - Successful: {results['exploitation_summary'].get('successful', 0)}")
        print(f"  - Failed: {results['exploitation_summary'].get('failed', 0)}")
        
        if "shells" in results and results["shells"]:
            print(f"\nObtained Shells: {len(results['shells'])}")
            for shell in results["shells"]:
                print(f"  - {shell.get('type', 'Unknown')} shell on {shell.get('target', 'Unknown')} ({shell.get('privileges', 'unknown')} privileges)")
    
    elif phase == "postexploit":
        # Print post-exploitation summary
        if "persistence" in results:
            print(f"Persistence Mechanisms: {len(results['persistence'])}")
            for mechanism in results["persistence"]:
                print(f"  - {mechanism.get('technique', 'Unknown')} on {mechanism.get('host', 'Unknown')}")
        
        if "data_exfiltration" in results:
            print(f"\nData Exfiltration:")
            total_data = sum(op.get("total_size", 0) for op in results["data_exfiltration"])
            print(f"  - Total data exfiltrated: {total_data / (1024*1024):.2f} MB")
            
            data_types = set()
            for op in results["data_exfiltration"]:
                for data_type in op.get("data_types", []):
                    data_types.add(data_type)
            
            if data_types:
                print(f"  - Types of data: {', '.join(data_types)}")
    
    print(f"\n{'=' * 50}")

def main():
    """Main function"""
    # Parse command-line arguments
    args = parse_arguments()
    
    # Set verbosity level
    verbosity = 0
    if args.quiet:
        verbosity = 0
    elif args.verbose:
        verbosity = 2
    else:
        verbosity = 1

    verify_ssl = not args.no_verify_ssl
    
    # Initialize the APTES framework
    framework = APTESFramework(
        target=args.target,
        output_dir=args.output_dir,
        threads=args.threads,
        verbosity=verbosity,
        verify_ssl=verify_ssl
    )
    
    # Print banner
    if verbosity > 0:
        framework.print_banner()
    
    # Load previous results if provided
    if args.results_file:
        if not framework.load_results(args.results_file):
            framework.logger.error(f"Failed to load results from {args.results_file}")
            return 1
    
    # Build risk level filter
    exploit_filter = None
    if args.filter != 'all':
        exploit_filter = {'risk_level': [args.filter]}
        if args.filter == 'critical':
            exploit_filter['risk_level'] = ['critical']
        elif args.filter == 'high':
            exploit_filter['risk_level'] = ['critical', 'high']
        elif args.filter == 'medium':
            exploit_filter['risk_level'] = ['critical', 'high', 'medium']
        elif args.filter == 'low':
            exploit_filter['risk_level'] = ['critical', 'high', 'medium', 'low']
    
    # Determine which phases to run
    phases = []
    if args.phase == 'all':
        phases = ['recon', 'preexploit', 'exploit', 'postexploit']
    else:
        phases = [args.phase]
    
    # Run the specified phases
    for phase in phases:
        framework.logger.info(f"Starting {phase} phase")
        
        try:
            if phase == 'recon':
                # Run reconnaissance phase
                success = framework.run_phase('recon', 
                                             passive_only=args.passive_only,
                                             skip_web=args.skip_web,
                                             use_ping_scan=args.ping_scan,
                                             use_netbios_scan=args.netbios_scan,
                                             use_aggressive_scan=args.aggressive_scan)
            
            elif phase == 'preexploit':
                # Run pre-exploitation phase
                success = framework.run_phase('preexploit',
                                             exploit_filter=exploit_filter,
                                             skip_web=args.skip_web,
                                             skip_creds=args.no_creds,
                                             skip_payloads=args.no_payloads)
            
            elif phase == 'exploit':
                # Run exploitation phase
                success = framework.run_phase('exploit',
                                             auto_exploit=args.auto_exploit,
                                             exploit_filter=exploit_filter)
            
            elif phase == 'postexploit':
                # Run post-exploitation phase
                success = framework.run_phase('postexploit',
                                             install_persistence=args.install_persistence,
                                             exfiltrate_data=args.exfiltrate_data,
                                             cleanup_traces=not args.no_cleanup)
            
            if not success:
                framework.logger.error(f"Failed to run {phase} phase")
                if phase != phases[-1]:  # Only exit if not the last phase
                    return 1
            
            # Print summary
            if verbosity > 0:
                print_summary(framework, phase)
                
            # Generate reports
            try:
                if phase == 'preexploit':
                    # Generate reports for pre-exploitation phase
                    phase_controller = getattr(framework, phase)
                    if hasattr(phase_controller, 'generate_report'):
                        report_files = phase_controller.generate_report(format=args.format)
                        framework.logger.info(f"Generated reports: {', '.join([f for f in report_files.values() if f])}")
            except Exception as e:
                framework.logger.error(f"Error generating reports: {str(e)}")
            
        except KeyboardInterrupt:
            framework.logger.error(f"{phase.capitalize()} phase interrupted by user")
            return 1
        except Exception as e:
            framework.logger.error(f"Error in {phase} phase: {str(e)}")
            if verbosity >= 2:
                import traceback
                traceback.print_exc()
            return 1
    
    # Save final results
    try:
        results_file = framework.save_results()
        framework.logger.info(f"Results saved to {results_file}")
    except Exception as e:
        framework.logger.error(f"Error saving results: {str(e)}")

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
