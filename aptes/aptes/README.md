# APTES - Advanced Penetration Testing and Exploitation Suite

APTES is a comprehensive security assessment framework for reconnaissance, pre-exploitation, exploitation, and post-exploitation phases.

## Features

- **Modular Design**: Clearly separated modules for different phases of penetration testing
- **Flexible Reporting**: Multiple report formats (JSON, Excel, Markdown)
- **Customizable Scanning**: Run specific phases or entire assessments
- **Web Application Analysis**: Scan for common web vulnerabilities
- **Vulnerability Validation**: Validate and enhance discovered vulnerabilities
- **Credential Testing**: Check for default credentials
- **Payload Generation**: Create payloads for identified vulnerabilities

## Installation

```bash
# Clone the repository
git clone https://github.com/byteshell/aptes.git
cd aptes

# Install the package
pip install .

# For full functionality including Excel reports
pip install .[full]
