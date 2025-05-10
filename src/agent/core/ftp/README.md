# FTP Scanner Module

This module is part of the AD Protect Agent and is designed to scan for FTP servers in an Active Directory environment and check for common vulnerabilities and misconfigurations.

## Features

- Discovers all servers in the domain using LDAP queries
- Scans for open FTP ports (21/TCP)
- Checks for common FTP vulnerabilities:
  - Anonymous access
  - FTP bounce attack vulnerability
  - Weak credentials
  - Outdated and vulnerable FTP server versions
  - Clear text credential transmission
- Supports both active and passive mode testing
- Multi-threaded scanning for efficient network-wide assessment

## Usage

```python
from ldap.ldap import LdapConnector
from ftp.ftp import FTPScanner

# Initialize LDAP connector
ldap_conn = LdapConnector(
    server_string="ldap://dc01.example.com",
    domain="example.com",
    username="ldapuser",
    password="password",
    method="NTLM"
)

# Initialize FTP scanner
ftp_scanner = FTPScanner(ldap_conn)

# Scan the entire network for FTP servers
results = ftp_scanner.scan_network_for_ftp()
print(results)

# Scan a specific server
server_result = ftp_scanner.scan_specific_server("fileserver.example.com")
print(server_result)

# Test credentials against a list of servers
servers = [
    {"hostname": "server1.example.com"},
    {"hostname": "server2.example.com"}
]
cred_test = ftp_scanner.scan_servers_with_credentials(servers, "testuser", "testpass")
print(cred_test)