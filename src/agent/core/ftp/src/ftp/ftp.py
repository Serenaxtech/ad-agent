import json
import logging
import socket
import ftplib
import tempfile
import os
from typing import Dict, List, Optional, Any, Union, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from ldap.ldap import LdapConnector
from config.config import Config
from logging_custom.logging_custom import configure_logging

ftp_logger = logging.getLogger(__name__)

class FTPScanner:
    """
    A module for scanning FTP servers in an Active Directory environment for vulnerabilities
    and misconfigurations. This module identifies servers with FTP ports open and checks for
    common security issues such as anonymous access, weak credentials, and outdated versions.
    """
    
    def __init__(self, ldap_connector: LdapConnector, max_threads: int = 10, timeout: int = 5):
        """
        Initialize the FTP Scanner module.
        
        Args:
            ldap_connector (LdapConnector): An initialized LDAP connector for AD queries
            max_threads (int): Maximum number of concurrent threads for scanning
            timeout (int): Connection timeout in seconds
        """
        self.ldap = ldap_connector
        self.max_threads = max_threads
        self.timeout = timeout
        self.ftp_port = 21
        configure_logging(ftp_logger, "ftp-module")
        ftp_logger.info("FTP Scanner module initialized")
    
    def get_domain_servers(self, as_json: bool = False) -> Union[str, List]:
        """
        Find all servers in the domain using LDAP.
        
        Args:
            as_json (bool): Whether to return results as JSON string or list
            
        Returns:
            Union[str, List]: JSON string or list containing servers
        """
        ftp_logger.info("Querying for servers in the domain")
        
        # LDAP filter to find all servers
        ldap_filter = "(objectCategory=computer)"
        attributes = ["dNSHostName", "operatingSystem", "operatingSystemVersion", "name"]
        
        try:
            results = self.ldap.query(ldapfilter=ldap_filter, attributes=attributes, as_json=False)
            
            servers = []
            for result in results:
                if result.get("dNSHostName"):
                    hostname = result.get("dNSHostName", "")
                    if hostname:  # Only include if hostname is not empty
                        server_info = {
                            "hostname": hostname,
                            "name": result.get("name", ""),
                            "os": result.get("operatingSystem", ""),
                            "os_version": result.get("operatingSystemVersion", "")
                        }
                        servers.append(server_info)
            
            ftp_logger.debug(f"Found {len(servers)} servers")
            return json.dumps(servers) if as_json else servers
            
        except Exception as e:
            ftp_logger.exception(f"Error querying for servers: {str(e)}")
            error_data = {
                "error": True,
                "message": str(e),
                "query": "domain servers",
                "status": "exception"
            }
            return json.dumps(error_data) if as_json else error_data
    
    def check_port_open(self, hostname: str, port: int = 21) -> bool:
        """
        Check if a specific port is open on a host.
        
        Args:
            hostname (str): The hostname to check
            port (int): The port number to check (default: 21 for FTP)
            
        Returns:
            bool: True if port is open, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((hostname, port))
            sock.close()
            return result == 0
        except Exception as e:
            ftp_logger.debug(f"Error checking port {port} on {hostname}: {str(e)}")
            return False
    
    def check_anonymous_access(self, hostname: str) -> Dict:
        """
        Check if FTP server allows anonymous access.
        
        Args:
            hostname (str): The hostname to check
            
        Returns:
            Dict: Results of the anonymous access check
        """
        result = {
            "hostname": hostname,
            "anonymous_access": False,
            "banner": "",
            "directory_listing": [],
            "error": None
        }
        
        try:
            ftp = ftplib.FTP()
            ftp.connect(hostname, self.ftp_port, timeout=self.timeout)
            result["banner"] = ftp.getwelcome()
            
            # Try anonymous login
            ftp.login()
            result["anonymous_access"] = True
            
            # Try to get directory listing
            try:
                result["directory_listing"] = ftp.nlst()
            except:
                result["directory_listing"] = []
            
            ftp.quit()
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def check_ftp_vulnerabilities(self, hostname: str) -> Dict:
        """
        Check for various FTP vulnerabilities and misconfigurations.
        
        Args:
            hostname (str): The hostname to check
            
        Returns:
            Dict: Results of the vulnerability checks
        """
        result = {
            "hostname": hostname,
            "port_open": False,
            "anonymous_access": False,
            "banner": "",
            "ftp_bounce": False,
            "allows_active_mode": False,
            "allows_passive_mode": False,
            "clear_text_credentials": True,  # FTP by default uses clear text
            "directory_listing": [],
            "version": "",
            "vulnerabilities": [],
            "error": None
        }
        
        # First check if port is open
        result["port_open"] = self.check_port_open(hostname, self.ftp_port)
        if not result["port_open"]:
            return result
        
        # Check anonymous access
        anon_result = self.check_anonymous_access(hostname)
        result["anonymous_access"] = anon_result["anonymous_access"]
        result["banner"] = anon_result["banner"]
        result["directory_listing"] = anon_result["directory_listing"]
        
        # Extract version information from banner
        if result["banner"]:
            result["version"] = self._extract_version_from_banner(result["banner"])
            
            # Check for known vulnerable versions
            vulnerabilities = self._check_known_vulnerabilities(result["version"])
            if vulnerabilities:
                result["vulnerabilities"].extend(vulnerabilities)
        
        # Check for FTP bounce attack vulnerability
        if result["anonymous_access"]:
            bounce_vulnerable = self._check_ftp_bounce(hostname)
            result["ftp_bounce"] = bounce_vulnerable
            if bounce_vulnerable:
                result["vulnerabilities"].append("FTP Bounce Attack")
        
        # Check for active/passive mode
        if result["anonymous_access"]:
            result["allows_active_mode"], result["allows_passive_mode"] = self._check_ftp_modes(hostname)
        
        # If anonymous access is allowed, add it as a vulnerability
        if result["anonymous_access"]:
            result["vulnerabilities"].append("Anonymous Access Allowed")
        
        return result
    
    def _extract_version_from_banner(self, banner: str) -> str:
        """
        Extract version information from FTP banner.
        
        Args:
            banner (str): The FTP server banner
            
        Returns:
            str: Extracted version information
        """
        # Common patterns for FTP server versions
        # This is a simplified approach - in production, you might want to use regex patterns
        version = ""
        
        # Look for common FTP server types
        server_types = ["FileZilla", "vsftpd", "ProFTPD", "Pure-FTPd", "Microsoft FTP", "IIS"]
        for server in server_types:
            if server.lower() in banner.lower():
                version = server
                # Try to extract version number
                parts = banner.split()
                for part in parts:
                    if part[0].isdigit() and "." in part:
                        version += " " + part
                        break
                break
        
        return version
    
    def _check_known_vulnerabilities(self, version: str) -> List[str]:
        """
        Check if the FTP server version has known vulnerabilities.
        
        Args:
            version (str): The FTP server version
            
        Returns:
            List[str]: List of vulnerability descriptions
        """
        vulnerabilities = []
        
        # This is a simplified approach - in production, you would have a more comprehensive database
        # of vulnerable versions and CVEs
        
        if "vsftpd 2.3.4" in version:
            vulnerabilities.append("vsftpd 2.3.4 Backdoor Vulnerability (CVE-2011-2523)")
        
        if "ProFTPD 1.3.3" in version:
            vulnerabilities.append("ProFTPD 1.3.3 Remote Code Execution (CVE-2010-4221)")
        
        if "FileZilla" in version and any(v in version for v in ["0.", "1.", "2.0"]):
            vulnerabilities.append("Outdated FileZilla Server with multiple vulnerabilities")
        
        if "IIS 5.0" in version or "IIS 6.0" in version:
            vulnerabilities.append("Outdated IIS FTP Service with multiple vulnerabilities")
        
        return vulnerabilities
    
    def _check_ftp_bounce(self, hostname: str) -> bool:
        """
        Check if the FTP server is vulnerable to FTP bounce attacks.
        
        Args:
            hostname (str): The hostname to check
            
        Returns:
            bool: True if vulnerable, False otherwise
        """
        try:
            ftp = ftplib.FTP()
            ftp.connect(hostname, self.ftp_port, timeout=self.timeout)
            
            # Try anonymous login
            try:
                ftp.login()
            except:
                ftp.close()
                return False
            
            # Try to use PORT command with an external IP
            # This is a simplified check - in a real scenario, you would try to connect to another host
            try:
                # Use a non-routable IP for testing (192.0.2.1 - TEST-NET-1)
                bounce_ip = "192.0.2.1"
                bounce_port = 12345  # Random port
                ip_parts = bounce_ip.split(".")
                port_hi = bounce_port // 256
                port_lo = bounce_port % 256
                
                # Format: h1,h2,h3,h4,p1,p2
                bounce_cmd = f"PORT {ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{port_hi},{port_lo}"
                
                # Send the PORT command directly
                ftp.sendcmd(bounce_cmd)
                
                # If we get here without an exception, the server accepted the PORT command
                # This indicates potential vulnerability to FTP bounce attacks
                ftp.quit()
                return True
            except:
                ftp.quit()
                return False
                
        except Exception as e:
            ftp_logger.debug(f"Error checking FTP bounce on {hostname}: {str(e)}")
            return False
    
    def _check_ftp_modes(self, hostname: str) -> Tuple[bool, bool]:
        """
        Check if the FTP server supports active and passive modes.
        
        Args:
            hostname (str): The hostname to check
            
        Returns:
            Tuple[bool, bool]: (active_mode_supported, passive_mode_supported)
        """
        active_mode = False
        passive_mode = False
        
        try:
            # Check active mode
            ftp = ftplib.FTP()
            ftp.connect(hostname, self.ftp_port, timeout=self.timeout)
            try:
                ftp.login()
                # By default, ftplib uses active mode
                ftp.nlst()
                active_mode = True
            except:
                pass
            ftp.quit()
            
            # Check passive mode
            ftp = ftplib.FTP()
            ftp.connect(hostname, self.ftp_port, timeout=self.timeout)
            try:
                ftp.login()
                ftp.set_pasv(True)
                ftp.nlst()
                passive_mode = True
            except:
                pass
            ftp.quit()
            
        except Exception as e:
            ftp_logger.debug(f"Error checking FTP modes on {hostname}: {str(e)}")
        
        return active_mode, passive_mode
    
    def scan_network_for_ftp(self, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan the entire network for FTP servers and check for vulnerabilities.
        
        Args:
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        ftp_logger.info("Starting network-wide FTP scan")
        
        scan_results = {
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "servers_scanned": 0,
            "ftp_servers_found": 0,
            "vulnerable_servers": 0,
            "results": []
        }
        
        try:
            # Get all servers in the domain
            servers = self.get_domain_servers(as_json=False)
            
            if isinstance(servers, dict) and servers.get("error"):
                return json.dumps(servers) if as_json else servers
            
            scan_results["servers_scanned"] = len(servers)
            
            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_server = {
                    executor.submit(self.check_ftp_vulnerabilities, server["hostname"]): server
                    for server in servers
                }
                
                for future in as_completed(future_to_server):
                    server = future_to_server[future]
                    try:
                        result = future.result()
                        if result["port_open"]:
                            scan_results["ftp_servers_found"] += 1
                            if result["vulnerabilities"]:
                                scan_results["vulnerable_servers"] += 1
                            scan_results["results"].append(result)
                    except Exception as e:
                        ftp_logger.error(f"Error scanning {server['hostname']}: {str(e)}")
                        scan_results["results"].append({
                            "hostname": server["hostname"],
                            "error": str(e),
                            "port_open": False,
                            "vulnerabilities": []
                        })
            
            ftp_logger.info(f"FTP scan completed. Found {scan_results['ftp_servers_found']} FTP servers, {scan_results['vulnerable_servers']} vulnerable")
            return json.dumps(scan_results) if as_json else scan_results
            
        except Exception as e:
            ftp_logger.exception(f"Error during FTP network scan: {str(e)}")
            error_data = {
                "error": True,
                "message": str(e),
                "scan": "network FTP scan",
                "status": "exception"
            }
            return json.dumps(error_data) if as_json else error_data
    
    def scan_specific_server(self, hostname: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan a specific server for FTP vulnerabilities.
        
        Args:
            hostname (str): The hostname to scan
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        ftp_logger.info(f"Scanning {hostname} for FTP vulnerabilities")
        
        try:
            result = self.check_ftp_vulnerabilities(hostname)
            return json.dumps(result) if as_json else result
            
        except Exception as e:
            ftp_logger.exception(f"Error scanning {hostname}: {str(e)}")
            error_data = {
                "error": True,
                "message": str(e),
                "hostname": hostname,
                "status": "exception"
            }
            return json.dumps(error_data) if as_json else error_data
    
    def scan_servers_with_credentials(self, servers: List[Dict], username: str, password: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan a list of servers using provided credentials to test for weak authentication.
        
        Args:
            servers (List[Dict]): List of server dictionaries with 'hostname' key
            username (str): Username to test
            password (str): Password to test
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        ftp_logger.info(f"Scanning servers with credentials test")
        
        scan_results = {
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "servers_scanned": len(servers),
            "successful_logins": 0,
            "results": []
        }
        
        try:
            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_server = {
                    executor.submit(self._test_credentials, server["hostname"], username, password): server
                    for server in servers
                }
                
                for future in as_completed(future_to_server):
                    server = future_to_server[future]
                    try:
                        result = future.result()
                        if result["login_successful"]:
                            scan_results["successful_logins"] += 1
                        scan_results["results"].append(result)
                    except Exception as e:
                        ftp_logger.error(f"Error testing credentials on {server['hostname']}: {str(e)}")
                        scan_results["results"].append({
                            "hostname": server["hostname"],
                            "error": str(e),
                            "login_successful": False
                        })
            
            ftp_logger.info(f"Credential test completed. Successful logins: {scan_results['successful_logins']}/{scan_results['servers_scanned']}")
            return json.dumps(scan_results) if as_json else scan_results
            
        except Exception as e:
            ftp_logger.exception(f"Error during credential test: {str(e)}")
            error_data = {
                "error": True,
                "message": str(e),
                "scan": "credential test",
                "status": "exception"
            }
            return json.dumps(error_data) if as_json else error_data
    
    def _test_credentials(self, hostname: str, username: str, password: str) -> Dict:
        """
        Test FTP login with specific credentials.
        
        Args:
            hostname (str): The hostname to test
            username (str): Username to test
            password (str): Password to test
            
        Returns:
            Dict: Results of the credential test
        """
        result = {
            "hostname": hostname,
            "username": username,
            "login_successful": False,
            "port_open": False,
            "directory_listing": [],
            "error": None
        }
        
        # First check if port is open
        result["port_open"] = self.check_port_open(hostname, self.ftp_port)
        if not result["port_open"]:
            return result
        
        try:
            ftp = ftplib.FTP()
            ftp.connect(hostname, self.ftp_port, timeout=self.timeout)
            
            # Try login with provided credentials
            ftp.login(username, password)
            result["login_successful"] = True
            
            # Try to get directory listing
            try:
                result["directory_listing"] = ftp.nlst()
            except:
                result["directory_listing"] = []
            
            ftp.quit()
        except Exception as e:
            result["error"] = str(e)
        
        return result