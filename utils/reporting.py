#!/usr/bin/env python3
"""
Reporting utilities for APTES
"""

import json
import logging
from datetime import datetime, date

logger = logging.getLogger('aptes.reporting')

# Check for optional dependencies
try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False
    logger.warning("openpyxl not available - Excel reporting disabled")

class ReportGenerator:
    """Report generation utilities for APTES"""
    
    def __init__(self, results, target, output_dir="reports"):
        """
        Initialize the report generator
        
        Args:
            results (dict): Results data to be reported
            target (str): Target of the assessment
            output_dir (str): Directory to save reports
        """
        self.results = results
        self.target = target
        self.output_dir = output_dir
        
        # Risk colors for Excel reports
        if EXCEL_AVAILABLE:
            self.risk_colors = {
                "critical": PatternFill(start_color="FF0000", end_color="FF0000", fill_type="solid"),
                "high": PatternFill(start_color="FFA500", end_color="FFA500", fill_type="solid"),
                "medium": PatternFill(start_color="FFFF00", end_color="FFFF00", fill_type="solid"),
                "low": PatternFill(start_color="00FF00", end_color="00FF00", fill_type="solid"),
                "info": PatternFill(start_color="ADD8E6", end_color="ADD8E6", fill_type="solid")
            }
    
    def generate_report(self, format="all", phase="preexploit"):
        """
        Generate report in specified format
        
        Args:
            format (str): Report format (json, excel, md, all)
            phase (str): Assessment phase to report on
        
        Returns:
            dict: Dictionary of generated report filenames
        """
        today = date.today().strftime("%Y%m%d")
        target_safe = self.target.replace(".", "_").replace(":", "_").replace("/", "_")
        base_filename = f"{self.output_dir}/{target_safe}_{phase}_{today}"
        
        report_files = {}
        
        if format in ["json", "all"]:
            json_file = f"{base_filename}.json"
            self.generate_json_report(json_file, phase)
            report_files["json"] = json_file
            
        if format in ["excel", "all"]:
            if EXCEL_AVAILABLE:
                excel_file = f"{base_filename}.xlsx"
                self.generate_excel_report(excel_file, phase)
                report_files["excel"] = excel_file
            else:
                logger.warning("Excel report skipped - openpyxl library not available")
                report_files["excel"] = None
            
        if format in ["md", "all"]:
            md_file = f"{base_filename}.md"
            self.generate_markdown_report(md_file, phase)
            report_files["markdown"] = md_file
            
        logger.info(f"Reports generated in {self.output_dir} directory")
        return report_files
    
    def generate_json_report(self, filename, phase="preexploit"):
        """
        Generate JSON report
        
        Args:
            filename (str): Output filename
            phase (str): Assessment phase to report on
        """
        data = self.results.get(phase, {})
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    
    def generate_excel_report(self, filename, phase="preexploit"):
        """
        Generate Excel report
        
        Args:
            filename (str): Output filename
            phase (str): Assessment phase to report on
        """
        if not EXCEL_AVAILABLE:
            logger.error("Cannot generate Excel report - openpyxl library not available")
            return
        
        # Get phase data
        data = self.results.get(phase, {})
        
        wb = Workbook()
        
        # Summary sheet
        summary = wb.active
        summary.title = "Summary"
        summary['A1'] = f"{phase.capitalize()} Report"
        summary['A1'].font = Font(bold=True, size=14)
        summary['A3'] = "Target:"
        summary['B3'] = self.target
        summary['A4'] = "Timestamp:"
        summary['B4'] = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # Phase-specific sheets
        if phase == "preexploit":
            self._add_preexploit_sheets(wb, data)
        elif phase == "recon":
            self._add_recon_sheets(wb, data)
        elif phase == "exploit":
            self._add_exploit_sheets(wb, data)
        elif phase == "postexploit":
            self._add_postexploit_sheets(wb, data)
        
        # Adjust column widths
        for sheet in wb.worksheets:
            for column in sheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                adjusted_width = (max_length + 2)
                sheet.column_dimensions[column_letter].width = min(adjusted_width, 50)
        
        # Save the workbook
        wb.save(filename)
    
    def _add_preexploit_sheets(self, workbook, data):
        """Add pre-exploitation sheets to Excel workbook"""
        # Vulnerabilities sheet
        if "vulnerability_validation" in data and "vulnerabilities" in data["vulnerability_validation"]:
            vulns_sheet = workbook.create_sheet("Vulnerabilities")
            vulns_sheet['A1'] = "Validated Vulnerabilities"
            vulns_sheet['A1'].font = Font(bold=True, size=14)
            
            vulns_sheet['A3'] = "Name"
            vulns_sheet['B3'] = "Host"
            vulns_sheet['C3'] = "Port"
            vulns_sheet['D3'] = "Service"
            vulns_sheet['E3'] = "Risk Level"
            vulns_sheet['F3'] = "CVE"
            vulns_sheet['G3'] = "Details"
            
            row = 4
            for vuln in data["vulnerability_validation"]["vulnerabilities"]:
                vulns_sheet[f'A{row}'] = vuln.get("vulnerability", "Unknown")
                vulns_sheet[f'B{row}'] = vuln.get("host", "Unknown")
                vulns_sheet[f'C{row}'] = vuln.get("port", "Unknown")
                vulns_sheet[f'D{row}'] = vuln.get("service", "Unknown")
                vulns_sheet[f'E{row}'] = vuln.get("risk_level", "Unknown")
                vulns_sheet[f'F{row}'] = vuln.get("cve", "N/A")
                vulns_sheet[f'G{row}'] = vuln.get("details", "No details available")
                
                risk = vuln.get("risk_level", "").lower()
                if risk in self.risk_colors:
                    vulns_sheet[f'E{row}'].fill = self.risk_colors[risk]
                
                row += 1
        
        # Web Findings sheet
        if "webapp_analysis" in data and "findings" in data["webapp_analysis"]:
            web_sheet = workbook.create_sheet("Web Findings")
            web_sheet['A1'] = "Web Application Findings"
            web_sheet['A1'].font = Font(bold=True, size=14)
            
            web_sheet['A3'] = "Finding"
            web_sheet['B3'] = "URL"
            web_sheet['C3'] = "Category"
            web_sheet['D3'] = "Risk Level"
            web_sheet['E3'] = "Description"
            web_sheet['F3'] = "Recommendation"
            
            row = 4
            for finding in data["webapp_analysis"]["findings"]:
                web_sheet[f'A{row}'] = finding.get("finding", "Unknown")
                host_port = f"{finding.get('host', '')}:{finding.get('port', '')}"
                web_sheet[f'B{row}'] = finding.get("url", host_port)
                web_sheet[f'C{row}'] = finding.get("category", "Unknown")
                web_sheet[f'D{row}'] = finding.get("risk_level", "Unknown")
                web_sheet[f'E{row}'] = finding.get("description", "No description available")
                web_sheet[f'F{row}'] = finding.get("recommendation", "No recommendation available")
                
                risk = finding.get("risk_level", "").lower()
                if risk in self.risk_colors:
                    web_sheet[f'D{row}'].fill = self.risk_colors[risk]
                
                row += 1
        
        # Attack Vectors sheet
        if "attack_vectors" in data:
            attack_sheet = workbook.create_sheet("Attack Vectors")
            attack_sheet['A1'] = "Attack Vectors"
            attack_sheet['A1'].font = Font(bold=True, size=14)
            
            attack_sheet['A3'] = "Vector"
            attack_sheet['B3'] = "Target"
            attack_sheet['C3'] = "Type"
            attack_sheet['D3'] = "Risk Level"
            attack_sheet['E3'] = "Description"
            
            row = 4
            for vector in data["attack_vectors"]:
                attack_sheet[f'A{row}'] = vector.get("name", "Unknown")
                attack_sheet[f'B{row}'] = vector.get("target", "Unknown")
                attack_sheet[f'C{row}'] = vector.get("type", "Unknown")
                attack_sheet[f'D{row}'] = vector.get("risk_level", "Unknown")
                attack_sheet[f'E{row}'] = vector.get("description", "No description available")
                
                risk = vector.get("risk_level", "").lower()
                if risk in self.risk_colors:
                    attack_sheet[f'D{row}'].fill = self.risk_colors[risk]
                
                row += 1
    
    def _add_recon_sheets(self, workbook, data):
        """Add reconnaissance sheets to Excel workbook"""
        # Passive recon sheet
        if "passive" in data:
            passive_sheet = workbook.create_sheet("Passive Recon")
            passive_sheet['A1'] = "Passive Reconnaissance Results"
            passive_sheet['A1'].font = Font(bold=True, size=14)
            
            # DNS Records
            row = 3
            if "dns" in data["passive"]:
                passive_sheet[f'A{row}'] = "DNS Records"
                passive_sheet[f'A{row}'].font = Font(bold=True)
                row += 1
                
                for record_type, records in data["passive"]["dns"].items():
                    passive_sheet[f'A{row}'] = f"{record_type} Records:"
                    col = 'B'
                    for record in records:
                        passive_sheet[f'{col}{row}'] = str(record)
                        col = chr(ord(col) + 1)
                    row += 1
                
                row += 1
            
            # Subdomains
            if "subdomains" in data["passive"]:
                passive_sheet[f'A{row}'] = "Subdomains"
                passive_sheet[f'A{row}'].font = Font(bold=True)
                row += 1
                
                for i, subdomain in enumerate(data["passive"]["subdomains"]):
                    passive_sheet[f'A{row}'] = subdomain
                    row += 1
                
                row += 1
            
            # SSL Info
            if "ssl_info" in data["passive"]:
                passive_sheet[f'A{row}'] = "SSL Certificate Information"
                passive_sheet[f'A{row}'].font = Font(bold=True)
                row += 1
                
                ssl_info = data["passive"]["ssl_info"]
                for key, value in ssl_info.items():
                    passive_sheet[f'A{row}'] = key.capitalize()
                    passive_sheet[f'B{row}'] = str(value)
                    row += 1
        
        # Active recon sheet
        if "active" in data:
            active_sheet = workbook.create_sheet("Active Recon")
            active_sheet['A1'] = "Active Reconnaissance Results"
            active_sheet['A1'].font = Font(bold=True, size=14)
            
            # Port scan results
            row = 3
            if "ports" in data["active"]:
                active_sheet[f'A{row}'] = "Port Scan Results"
                active_sheet[f'A{row}'].font = Font(bold=True)
                row += 1
                
                active_sheet[f'A{row}'] = "Host"
                active_sheet[f'B{row}'] = "Protocol"
                active_sheet[f'C{row}'] = "Port"
                active_sheet[f'D{row}'] = "State"
                active_sheet[f'E{row}'] = "Service"
                row += 1
                
                for host, host_data in data["active"]["ports"].items():
                    for proto, proto_data in host_data.items():
                        for port, port_data in proto_data.items():
                            active_sheet[f'A{row}'] = host
                            active_sheet[f'B{row}'] = proto
                            active_sheet[f'C{row}'] = port
                            active_sheet[f'D{row}'] = port_data.get("state", "unknown")
                            active_sheet[f'E{row}'] = port_data.get("service", "unknown")
                            row += 1
                
                row += 1
        
        # Web crawler results sheet
        if "webcrawler" in data:
            crawler_sheet = workbook.create_sheet("Web Crawler")
            crawler_sheet['A1'] = "Web Crawler Results"
            crawler_sheet['A1'].font = Font(bold=True, size=14)
            
            row = 3
            crawler_sheet[f'A{row}'] = "Summary"
            crawler_sheet[f'A{row}'].font = Font(bold=True)
            row += 1
            
            crawler_sheet[f'A{row}'] = "Crawled URLs:"
            crawler_sheet[f'B{row}'] = data["webcrawler"].get("crawled_urls", 0)
            row += 1
            
            crawler_sheet[f'A{row}'] = "Forms Found:"
            crawler_sheet[f'B{row}'] = data["webcrawler"].get("forms_found", 0)
            row += 1
            
            crawler_sheet[f'A{row}'] = "Potential Vulnerable URLs:"
            crawler_sheet[f'B{row}'] = len(data["webcrawler"].get("potential_vulnerable_urls", []))
            row += 2
            
            # Display forms
            if "sitemap" in data["webcrawler"]:
                crawler_sheet[f'A{row}'] = "Forms"
                crawler_sheet[f'A{row}'].font = Font(bold=True)
                row += 1
                
                crawler_sheet[f'A{row}'] = "URL"
                crawler_sheet[f'B{row}'] = "Form Action"
                crawler_sheet[f'C{row}'] = "Method"
                crawler_sheet[f'D{row}'] = "Input Fields"
                row += 1
                
                for url, page_data in data["webcrawler"]["sitemap"].items():
                    if "forms" in page_data and page_data["forms"]:
                        for form in page_data["forms"]:
                            crawler_sheet[f'A{row}'] = form.get("form_url", url)
                            crawler_sheet[f'B{row}'] = form.get("action", "")
                            crawler_sheet[f'C{row}'] = form.get("method", "GET")
                            crawler_sheet[f'D{row}'] = ", ".join([f"{input.get('name', '')} ({input.get('type', '')})" 
                                                              for input in form.get("inputs", [])])
                            row += 1
                
    def _add_exploit_sheets(self, workbook, data):
        """Add exploitation sheets to Excel workbook"""
        # Exploitation summary sheet
        summary_sheet = workbook.create_sheet("Exploitation Summary")
        summary_sheet['A1'] = "Exploitation Results"
        summary_sheet['A1'].font = Font(bold=True, size=14)
        
        row = 3
        if "exploitation_summary" in data:
            summary = data["exploitation_summary"]
            summary_sheet[f'A{row}'] = "Attempts:"
            summary_sheet[f'B{row}'] = summary.get("attempts", 0)
            row += 1
            
            summary_sheet[f'A{row}'] = "Successful:"
            summary_sheet[f'B{row}'] = summary.get("successful", 0)
            row += 1
            
            summary_sheet[f'A{row}'] = "Failed:"
            summary_sheet[f'B{row}'] = summary.get("failed", 0)
            row += 2
        
        # Exploits sheet
        if "exploits" in data:
            summary_sheet[f'A{row}'] = "Exploits Used"
            summary_sheet[f'A{row}'].font = Font(bold=True)
            row += 1
            
            summary_sheet[f'A{row}'] = "Name"
            summary_sheet[f'B{row}'] = "Target"
            summary_sheet[f'C{row}'] = "Success"
            summary_sheet[f'D{row}'] = "Details"
            row += 1
            
            for exploit in data["exploits"]:
                summary_sheet[f'A{row}'] = exploit.get("name", "Unknown")
                summary_sheet[f'B{row}'] = exploit.get("target", "Unknown")
                summary_sheet[f'C{row}'] = "Yes" if exploit.get("success", False) else "No"
                summary_sheet[f'D{row}'] = exploit.get("details", "")
                row += 1
        
        # Shells sheet
        if "shells" in data and data["shells"]:
            shells_sheet = workbook.create_sheet("Shells")
            shells_sheet['A1'] = "Obtained Shells"
            shells_sheet['A1'].font = Font(bold=True, size=14)
            
            shells_sheet['A3'] = "Type"
            shells_sheet['B3'] = "Target"
            shells_sheet['C3'] = "Port"
            shells_sheet['D3'] = "Privileges"
            shells_sheet['E3'] = "Notes"
            
            row = 4
            for shell in data["shells"]:
                shells_sheet[f'A{row}'] = shell.get("type", "Unknown")
                shells_sheet[f'B{row}'] = shell.get("target", "Unknown")
                shells_sheet[f'C{row}'] = shell.get("port", "Unknown")
                shells_sheet[f'D{row}'] = shell.get("privileges", "Unknown")
                shells_sheet[f'E{row}'] = shell.get("notes", "")
                row += 1
    
    def _add_postexploit_sheets(self, workbook, data):
        """Add post-exploitation sheets to Excel workbook"""
        # Post-exploitation summary sheet
        summary_sheet = workbook.create_sheet("Post-Exploitation")
        summary_sheet['A1'] = "Post-Exploitation Results"
        summary_sheet['A1'].font = Font(bold=True, size=14)
        
        # Persistence mechanisms
        row = 3
        if "persistence" in data and data["persistence"]:
            summary_sheet[f'A{row}'] = "Persistence Mechanisms"
            summary_sheet[f'A{row}'].font = Font(bold=True)
            row += 1
            
            summary_sheet[f'A{row}'] = "Host"
            summary_sheet[f'B{row}'] = "Technique"
            summary_sheet[f'C{row}'] = "Location"
            summary_sheet[f'D{row}'] = "Notes"
            row += 1
            
            for mechanism in data["persistence"]:
                summary_sheet[f'A{row}'] = mechanism.get("host", "Unknown")
                summary_sheet[f'B{row}'] = mechanism.get("technique", "Unknown")
                summary_sheet[f'C{row}'] = mechanism.get("location", "Unknown")
                summary_sheet[f'D{row}'] = mechanism.get("notes", "")
                row += 1
            
            row += 1
        
        # Data exfiltration
        if "data_exfiltration" in data and data["data_exfiltration"]:
            summary_sheet[f'A{row}'] = "Data Exfiltration"
            summary_sheet[f'A{row}'].font = Font(bold=True)
            row += 1
            
            summary_sheet[f'A{row}'] = "Host"
            summary_sheet[f'B{row}'] = "Data Type"
            summary_sheet[f'C{row}'] = "Size"
            summary_sheet[f'D{row}'] = "Location"
            row += 1
            
            for exfil in data["data_exfiltration"]:
                summary_sheet[f'A{row}'] = exfil.get("host", "Unknown")
                summary_sheet[f'B{row}'] = ", ".join(exfil.get("data_types", ["Unknown"]))
                summary_sheet[f'C{row}'] = f"{exfil.get('total_size', 0) / (1024*1024):.2f} MB"
                summary_sheet[f'D{row}'] = exfil.get("location", "Unknown")
                row += 1
    
    def generate_markdown_report(self, filename, phase="preexploit"):
        """
        Generate Markdown report
        
        Args:
            filename (str): Output filename
            phase (str): Assessment phase to report on
        """
        data = self.results.get(phase, {})
        
        with open(filename, "w") as f:
            f.write(f"# {phase.capitalize()} Report\n\n")
            f.write(f"## Target: {self.target}\n")
            f.write(f"## Timestamp: {data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n\n")
            
            # Phase-specific content
            if phase == "preexploit":
                self._write_preexploit_markdown(f, data)
            elif phase == "recon":
                self._write_recon_markdown(f, data)
            elif phase == "exploit":
                self._write_exploit_markdown(f, data)
            elif phase == "postexploit":
                self._write_postexploit_markdown(f, data)
            
            f.write(f"\n*Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")
    
    def _write_preexploit_markdown(self, file, data):
        """Write pre-exploitation markdown content"""
        # Summary section
        file.write(f"## Summary\n\n")
        
        if "vulnerability_validation" in data:
            vuln_count = data["vulnerability_validation"].get("total_count", 0)
            file.write(f"- **Total Vulnerabilities:** {vuln_count}\n")
            
            # Count by risk level
            if "vulnerabilities" in data["vulnerability_validation"]:
                risk_levels = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                for vuln in data["vulnerability_validation"]["vulnerabilities"]:
                    risk = vuln.get("risk_level", "info").lower()
                    if risk in risk_levels:
                        risk_levels[risk] += 1
                
                for risk, count in risk_levels.items():
                    if count > 0:
                        file.write(f"  - {risk.capitalize()}: {count}\n")
                
                file.write("\n")
        
        # Web findings
        if "webapp_analysis" in data:
            web_count = data["webapp_analysis"].get("total_findings", 0)
            file.write(f"- **Web Application Findings:** {web_count}\n")
            
            # Categories
            if "grouped_findings" in data["webapp_analysis"]:
                for category, findings in data["webapp_analysis"]["grouped_findings"].items():
                    file.write(f"  - {category}: {len(findings)}\n")
                
                file.write("\n")
        
        # Attack vectors
        if "attack_vectors" in data:
            attack_count = len(data["attack_vectors"])
            file.write(f"- **Attack Vectors:** {attack_count}\n\n")
        
        # Vulnerabilities
        if "vulnerability_validation" in data and "vulnerabilities" in data["vulnerability_validation"]:
            file.write(f"## Validated Vulnerabilities\n\n")
            
            # Group by risk level
            for risk in ["critical", "high", "medium", "low", "info"]:
                risk_vulns = [v for v in data["vulnerability_validation"]["vulnerabilities"] if v.get("risk_level") == risk]
                
                if risk_vulns:
                    file.write(f"### {risk.capitalize()} Risk Vulnerabilities\n\n")
                    
                    for vuln in risk_vulns:
                        file.write(f"#### {vuln.get('vulnerability', 'Unknown')}\n\n")
                        file.write(f"- **Host:** {vuln.get('host', 'Unknown')}\n")
                        file.write(f"- **Port:** {vuln.get('port', 'Unknown')}\n")
                        file.write(f"- **Service:** {vuln.get('service', 'Unknown')}\n")
                        
                        if "cve" in vuln:
                            file.write(f"- **CVE:** {vuln['cve']}\n")
                        
                        if "details" in vuln:
                            file.write(f"- **Details:** {vuln['details']}\n")
                        elif "description" in vuln:
                            file.write(f"- **Description:** {vuln['description']}\n")
                        
                        file.write("\n")
        
        # Web findings
        if "webapp_analysis" in data and "findings" in data["webapp_analysis"]:
            file.write(f"## Web Application Findings\n\n")
            
            # Group by category
            if "grouped_findings" in data["webapp_analysis"]:
                for category, findings in data["webapp_analysis"]["grouped_findings"].items():
                    file.write(f"### {category}\n\n")
                    
                    for finding in findings:
                        file.write(f"#### {finding.get('finding', 'Unknown')}\n\n")
                        host_port = f"{finding.get('host', '')}:{finding.get('port', '')}"
                        file.write(f"- **URL:** {finding.get('url', host_port)}\n")
                        file.write(f"- **Risk Level:** {finding.get('risk_level', 'Unknown')}\n")
                        file.write(f"- **Description:** {finding.get('description', 'No description available')}\n")
                        file.write(f"- **Recommendation:** {finding.get('recommendation', 'No recommendation available')}\n\n")
            else:
                # Fallback to flat list
                for finding in data["webapp_analysis"]["findings"]:
                    file.write(f"### {finding.get('finding', 'Unknown')}\n\n")
                    host_port = f"{finding.get('host', '')}:{finding.get('port', '')}"
                    file.write(f"- **URL:** {finding.get('url', host_port)}\n")
                    file.write(f"- **Category:** {finding.get('category', 'Unknown')}\n")
                    file.write(f"- **Risk Level:** {finding.get('risk_level', 'Unknown')}\n")
                    file.write(f"- **Description:** {finding.get('description', 'No description available')}\n")
                    file.write(f"- **Recommendation:** {finding.get('recommendation', 'No recommendation available')}\n\n")
        
        # Attack vectors
        if "attack_vectors" in data:
            file.write(f"## Attack Vectors\n\n")
            
            file.write(f"| Vector | Target | Type | Risk Level |\n")
            file.write(f"|--------|--------|------|------------|\n")
            
            for vector in data["attack_vectors"]:
                file.write(f"| {vector.get('name', 'Unknown')} | {vector.get('target', 'Unknown')} | {vector.get('type', 'Unknown')} | {vector.get('risk_level', 'Unknown')} |\n")
            
            file.write("\n")
        
        # Recommendations
        file.write(f"## Recommendations\n\n")
        
        # Extract recommendations from findings
        recommendations = set()
        
        if "webapp_analysis" in data and "findings" in data["webapp_analysis"]:
            for finding in data["webapp_analysis"]["findings"]:
                if "recommendation" in finding and finding.get("risk_level") in ["critical", "high", "medium"]:
                    recommendations.add(finding["recommendation"])
        
        # Add generic recommendations
        if not recommendations:
            recommendations = {
                "Implement proper input validation for all user inputs",
                "Enable security headers on web servers",
                "Regularly update and patch software",
                "Implement strong password policies",
                "Remove or secure default accounts"
            }
        
        # Write recommendations
        for rec in recommendations:
            file.write(f"- {rec}\n")
    
    def _write_recon_markdown(self, file, data):
        """Write reconnaissance markdown content"""
        # Passive reconnaissance
        if "passive" in data:
            file.write("## Passive Reconnaissance\n\n")
            
            # DNS records
            if "dns" in data["passive"]:
                file.write("### DNS Records\n\n")
                
                for record_type, records in data["passive"]["dns"].items():
                    if records:
                        file.write(f"#### {record_type} Records\n\n")
                        for record in records:
                            file.write(f"- {record}\n")
                        file.write("\n")
            
            # Subdomains
            if "subdomains" in data["passive"] and data["passive"]["subdomains"]:
                file.write("### Subdomains\n\n")
                
                for subdomain in data["passive"]["subdomains"]:
                    file.write(f"- {subdomain}\n")
                
                file.write("\n")
            
            # SSL info
            if "ssl_info" in data["passive"] and data["passive"]["ssl_info"]:
                file.write("### SSL Certificate Information\n\n")
                
                ssl_info = data["passive"]["ssl_info"]
                for key, value in ssl_info.items():
                    file.write(f"- **{key.capitalize()}:** {value}\n")
                
                file.write("\n")
        
        # Active reconnaissance
        if "active" in data:
            file.write("## Active Reconnaissance\n\n")
            
            # Port scan
            if "ports" in data["active"]:
                file.write("### Port Scan Results\n\n")
                
                file.write("| Host | Protocol | Port | State | Service |\n")
                file.write("|------|----------|------|-------|--------|\n")
                
                for host, host_data in data["active"]["ports"].items():
                    for proto, proto_data in host_data.items():
                        for port, port_data in proto_data.items():
                            state = port_data.get("state", "unknown")
                            service = port_data.get("service", "unknown")
                            file.write(f"| {host} | {proto} | {port} | {state} | {service} |\n")
                
                file.write("\n")
            
            # Web scan
            if "web" in data["active"]:
                file.write("### Web Scan Results\n\n")
                
                web_data = data["active"]["web"]
                
                # Technologies
                if "technologies" in web_data and web_data["technologies"]:
                    file.write("#### Web Technologies\n\n")
                    
                    for tech in web_data["technologies"]:
                        file.write(f"- {tech}\n")
                    
                    file.write("\n")
                
                # Headers
                if "headers" in web_data:
                    file.write("#### Web Headers\n\n")
                    
                    for url, headers in web_data["headers"].items():
                        file.write(f"**{url}**\n\n")
                        
                        for header, value in headers.items():
                            file.write(f"- {header}: {value}\n")
                        
                        file.write("\n")
                
                # Interesting files
                if "interesting_files" in web_data and web_data["interesting_files"]:
                    file.write("#### Interesting Files\n\n")
                    
                    for file_info in web_data["interesting_files"]:
                        file.write(f"- **{file_info.get('url', 'Unknown')}**\n")
                        if "content" in file_info:
                            file.write(f"  - Preview: {file_info['content'][:100]}...\n")
                    
                    file.write("\n")
        
        # Web crawler results
        if "webcrawler" in data:
            file.write("## Web Crawler Results\n\n")
            
            file.write(f"- **Crawled URLs:** {data['webcrawler'].get('crawled_urls', 0)}\n")
            file.write(f"- **Forms Found:** {data['webcrawler'].get('forms_found', 0)}\n")
            file.write(f"- **Potential Vulnerable URLs:** {len(data['webcrawler'].get('potential_vulnerable_urls', []))}\n\n")
            
            # List forms found
            if "sitemap" in data["webcrawler"]:
                file.write("### Forms Found\n\n")
                
                # Create a table for forms
                file.write("| Form URL | Action | Method | Inputs |\n")
                file.write("|----------|--------|--------|--------|\n")
                
                for url, page_data in data["webcrawler"]["sitemap"].items():
                    if "forms" in page_data and page_data["forms"]:
                        for form in page_data["forms"]:
                            form_url = form.get("form_url", url)
                            action = form.get("action", "")
                            method = form.get("method", "GET")
                            
                            # Format inputs in a readable way
                            inputs = ", ".join([f"{input.get('name', '')} ({input.get('type', '')})" 
                                              for input in form.get("inputs", [])])
                            
                            file.write(f"| {form_url} | {action} | {method} | {inputs} |\n")
                
                file.write("\n")
                
                # Detailed form information
                file.write("### Detailed Form Information\n\n")
                
                form_count = 0
                for url, page_data in data["webcrawler"]["sitemap"].items():
                    if "forms" in page_data and page_data["forms"]:
                        for form in page_data["forms"]:
                            form_count += 1
                            form_url = form.get("form_url", url)
                            
                            file.write(f"#### Form #{form_count} - {form_url}\n\n")
                            file.write(f"- **Action:** {form.get('action', '')}\n")
                            file.write(f"- **Method:** {form.get('method', 'GET')}\n")
                            
                            # List all form inputs
                            if "inputs" in form and form["inputs"]:
                                file.write("- **Inputs:**\n")
                                
                                for input_field in form["inputs"]:
                                    input_type = input_field.get("type", "")
                                    input_name = input_field.get("name", "")
                                    input_value = input_field.get("value", "")
                                    
                                    file.write(f"  - {input_name} ({input_type})")
                                    if input_value:
                                        file.write(f" = {input_value}")
                                    file.write("\n")
                            
                            file.write("\n")
    
    def _write_exploit_markdown(self, file, data):
        """Write exploitation markdown content"""
        # Summary
        if "exploitation_summary" in data:
            summary = data["exploitation_summary"]
            file.write("## Exploitation Summary\n\n")
            file.write(f"- **Attempts:** {summary.get('attempts', 0)}\n")
            file.write(f"- **Successful:** {summary.get('successful', 0)}\n")
            file.write(f"- **Failed:** {summary.get('failed', 0)}\n\n")
        
        # Exploits
        if "exploits" in data and data["exploits"]:
            file.write("## Exploits Used\n\n")
            
            file.write("| Name | Target | Success | Details |\n")
            file.write("|------|--------|---------|--------|\n")
            
            for exploit in data["exploits"]:
                success = "Yes" if exploit.get("success", False) else "No"
                name = exploit.get("name", "Unknown")
                target = exploit.get("target", "Unknown")
                details = exploit.get("details", "")
                file.write(f"| {name} | {target} | {success} | {details} |\n")
            
            file.write("\n")
        
        # Shells
        if "shells" in data and data["shells"]:
            file.write("## Obtained Shells\n\n")
            
            file.write("| Type | Target | Port | Privileges | Notes |\n")
            file.write("|------|--------|------|------------|-------|\n")
            
            for shell in data["shells"]:
                shell_type = shell.get("type", "Unknown")
                target = shell.get("target", "Unknown")
                port = shell.get("port", "Unknown")
                privs = shell.get("privileges", "Unknown")
                notes = shell.get("notes", "")
                file.write(f"| {shell_type} | {target} | {port} | {privs} | {notes} |\n")
            
            file.write("\n")
        
        # Privilege escalation
        if "privilege_escalation" in data and data["privilege_escalation"]:
            file.write("## Privilege Escalation\n\n")
            
            for pe in data["privilege_escalation"]:
                file.write(f"### {pe.get('technique', 'Unknown')}\n\n")
                file.write(f"- **Target:** {pe.get('target', 'Unknown')}\n")
                file.write(f"- **Initial User:** {pe.get('initial_user', 'Unknown')}\n")
                file.write(f"- **Escalated User:** {pe.get('escalated_user', 'Unknown')}\n")
                
                if "details" in pe:
                    file.write(f"- **Details:** {pe['details']}\n")
                
                file.write("\n")
    
    def _write_postexploit_markdown(self, file, data):
        """Write post-exploitation markdown content"""
        # Persistence
        if "persistence" in data and data["persistence"]:
            file.write("## Persistence Mechanisms\n\n")
            
            file.write("| Host | Technique | Location | Notes |\n")
            file.write("|------|-----------|----------|-------|\n")
            
            for mechanism in data["persistence"]:
                host = mechanism.get("host", "Unknown")
                technique = mechanism.get("technique", "Unknown")
                location = mechanism.get("location", "Unknown")
                notes = mechanism.get("notes", "")
                file.write(f"| {host} | {technique} | {location} | {notes} |\n")
            
            file.write("\n")
        
        # Data exfiltration
        if "data_exfiltration" in data and data["data_exfiltration"]:
            file.write("## Data Exfiltration\n\n")
            
            total_data = sum(op.get("total_size", 0) for op in data["data_exfiltration"])
            file.write(f"**Total data exfiltrated:** {total_data / (1024*1024):.2f} MB\n\n")
            
            file.write("| Host | Data Type | Size | Location |\n")
            file.write("|------|-----------|------|----------|\n")
            
            for exfil in data["data_exfiltration"]:
                host = exfil.get("host", "Unknown")
                data_types = ", ".join(exfil.get("data_types", ["Unknown"]))
                size = f"{exfil.get('total_size', 0) / (1024*1024):.2f} MB"
                location = exfil.get("location", "Unknown")
                file.write(f"| {host} | {data_types} | {size} | {location} |\n")
            
            file.write("\n")
        
        # Evidence removal
        if "evidence_removal" in data and data["evidence_removal"]:
            file.write("## Evidence Removal\n\n")
            
            for cleanup in data["evidence_removal"]:
                file.write(f"### {cleanup.get('host', 'Unknown')}\n\n")
                file.write(f"- **Actions:** {', '.join(cleanup.get('actions', []))}\n")
                
                if "details" in cleanup:
                    file.write(f"- **Details:** {cleanup['details']}\n")
                
                if "success" in cleanup:
                    success = "Yes" if cleanup["success"] else "No"
                    file.write(f"- **Success:** {success}\n")
                
                file.write("\n")
