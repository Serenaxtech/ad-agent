import json
import logging
import subprocess
import os
import tempfile
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import re

from ldap.ldap import LdapConnector
from config.config import Config
from logging_custom.logging_custom import configure_logging

adcs_logger = logging.getLogger(__name__)

class ADCSScanner:
    """
    A module for scanning Active Directory Certificate Services (ADCS) for vulnerabilities
    using Certipy. This module identifies vulnerable certificate templates and other ADCS
    misconfigurations that could be exploited.
    """
    
    def __init__(self, ldap_connector: LdapConnector):
        """
        Initialize the ADCS Scanner module.
        
        Args:
            ldap_connector (LdapConnector): An initialized LDAP connector for AD queries
        """
        self.ldap = ldap_connector
        configure_logging(adcs_logger, "adcs-module")
        adcs_logger.info("ADCS Scanner module initialized")
        
        # Verify Docker is available
        self._verify_docker_installation()
        
        # Docker image for Certipy
        self.docker_image = "adprotect/certipy:latest"
        
    def _verify_docker_installation(self) -> None:
        """
        Verify that Docker is installed and available.
        Raises a RuntimeError if Docker is not found.
        """
        try:
            result = subprocess.run(
                ["docker", "--version"], 
                capture_output=True, 
                text=True, 
                check=False
            )
            if result.returncode != 0:
                adcs_logger.error("Docker not found or not working properly")
                raise RuntimeError("Docker not found or not working properly. Please install Docker.")
            adcs_logger.debug(f"Docker version: {result.stdout.strip()}")
            
            # Check if the Certipy image exists
            result = subprocess.run(
                ["docker", "image", "inspect", self.docker_image],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                adcs_logger.info(f"Certipy Docker image not found.")
        
        except FileNotFoundError:
            adcs_logger.error("Docker not found in PATH")
            adcs_logger.error("Docker not found. Please install Docker.")
            exit(-1)
    
    def scan_vulnerable_templates(self, domain: str, username: str, password: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan for vulnerable certificate templates using Certipy's find command.
        
        Args:
            domain (str): The domain to scan
            username (str): Username for authentication
            password (str): Password for authentication
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing vulnerable templates
        """
        adcs_logger.info(f"Scanning for vulnerable certificate templates in domain: {domain}")
        
        # Create a temporary directory for output files
        temp_dir = tempfile.mkdtemp(prefix="certipy_")
        temp_path = os.path.join(temp_dir, "output.json")
        
        try:
            # Prepare Docker command to run Certipy
            docker_cmd = [
                "docker", "run", "--rm",
                "-v", f"{temp_dir}:/data",
                "--network", "host",  # Use host network for domain resolution
                self.docker_image,
                "certipy", "find", 
                "-u", f"{username}@{domain}",
                "-p", password,
                "-vulnerable",
                "-json", "/data/output.json",
                "-stdout"
            ]
            
            adcs_logger.debug(f"Running Docker command: docker run --rm -v {temp_dir}:/data --network host {self.docker_image} certipy find -u {username}@{domain} -p *** -vulnerable -json /data/output.json -stdout")
            
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                adcs_logger.error(f"Certipy Docker command failed: {result.stderr}")
                error_data = {
                    "error": True,
                    "message": result.stderr,
                    "command": "docker run certipy find",
                    "status": "failed"
                }
                return json.dumps(error_data) if as_json else error_data
            
            # Check if the output file exists
            if not os.path.exists(temp_path):
                adcs_logger.error("Certipy output file not found")
                error_data = {
                    "error": True,
                    "message": "Certipy output file not found. Docker container may not have proper permissions or volume mapping.",
                    "command": "docker run certipy find",
                    "status": "failed"
                }
                return json.dumps(error_data) if as_json else error_data
            
            # Read the JSON output file
            with open(temp_path, 'r') as f:
                scan_data = json.load(f)
            
            # Process and structure the results
            processed_results = self._process_certipy_results(scan_data)
            
            return json.dumps(processed_results) if as_json else processed_results
            
        except Exception as e:
            adcs_logger.exception(f"Error scanning for vulnerable templates: {str(e)}")
            error_data = {
                "error": True,
                "message": str(e),
                "command": "docker run certipy find",
                "status": "exception"
            }
            return json.dumps(error_data) if as_json else error_data
        finally:
            # Clean up the temporary directory
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
    
    def _process_certipy_results(self, certipy_data: Dict) -> Dict:
        """
        Process and structure the raw Certipy output into a well-defined format.
        
        Args:
            certipy_data (Dict): Raw data from Certipy JSON output
            
        Returns:
            Dict: Processed and structured results
        """
        processed_data = {
            "scan_timestamp": certipy_data.get("timestamp", ""),
            "domain": certipy_data.get("domain", ""),
            "cas": [],
            "templates": [],
            "vulnerabilities": {
                "esc1": [],  # Template allows client authentication and enrollee supplies subject
                "esc2": [],  # Template allows requesters to specify subjectAltName
                "esc3": [],  # Template allows enrollment agent templates
                "esc4": [],  # Template has vulnerable certificate authorities
                "esc5": [],  # Template allows user certificates on behalf of other users
                "esc6": [],  # Template allows DNS or hostname request
                "esc7": [],  # Template allows vulnerable certificate authorities with web enrollment
                "esc8": [],  # Template allows NTLM relay
                "other": []
            },
            "summary": {
                "total_cas": 0,
                "total_templates": 0,
                "total_vulnerable_templates": 0,
                "vulnerability_counts": {}
            }
        }
        
        # Process Certificate Authorities
        if "certificate_authorities" in certipy_data:
            for ca_name, ca_data in certipy_data["certificate_authorities"].items():
                ca_info = {
                    "name": ca_name,
                    "dns_name": ca_data.get("dns_name", ""),
                    "ca_name": ca_data.get("ca_name", ""),
                    "web_enrollment": ca_data.get("web_enrollment", False),
                    "vulnerable_to_ntlm_relay": ca_data.get("vulnerable_to_ntlm_relay", False)
                }
                processed_data["cas"].append(ca_info)
            
            processed_data["summary"]["total_cas"] = len(processed_data["cas"])
        
        # Process Templates
        if "certificate_templates" in certipy_data:
            for template_name, template_data in certipy_data["certificate_templates"].items():
                template_info = {
                    "name": template_name,
                    "display_name": template_data.get("display_name", ""),
                    "schema_version": template_data.get("schema_version", ""),
                    "validity_period": template_data.get("validity_period", ""),
                    "renewal_period": template_data.get("renewal_period", ""),
                    "owner": template_data.get("owner", ""),
                    "enrollee_supplies_subject": template_data.get("enrollee_supplies_subject", False),
                    "client_authentication": template_data.get("client_authentication", False),
                    "enrollment_agent": template_data.get("enrollment_agent", False),
                    "vulnerable_aces": template_data.get("vulnerable_aces", []),
                    "vulnerabilities": []
                }
                
                # Check for vulnerabilities
                if template_data.get("vulnerabilities"):
                    for vuln in template_data["vulnerabilities"]:
                        template_info["vulnerabilities"].append(vuln)
                        
                        # Add to appropriate vulnerability category
                        if "ESC1" in vuln:
                            processed_data["vulnerabilities"]["esc1"].append(template_name)
                        elif "ESC2" in vuln:
                            processed_data["vulnerabilities"]["esc2"].append(template_name)
                        elif "ESC3" in vuln:
                            processed_data["vulnerabilities"]["esc3"].append(template_name)
                        elif "ESC4" in vuln:
                            processed_data["vulnerabilities"]["esc4"].append(template_name)
                        elif "ESC5" in vuln:
                            processed_data["vulnerabilities"]["esc5"].append(template_name)
                        elif "ESC6" in vuln:
                            processed_data["vulnerabilities"]["esc6"].append(template_name)
                        elif "ESC7" in vuln:
                            processed_data["vulnerabilities"]["esc7"].append(template_name)
                        elif "ESC8" in vuln:
                            processed_data["vulnerabilities"]["esc8"].append(template_name)
                        else:
                            processed_data["vulnerabilities"]["other"].append(template_name)
                
                processed_data["templates"].append(template_info)
            
            processed_data["summary"]["total_templates"] = len(processed_data["templates"])
            processed_data["summary"]["total_vulnerable_templates"] = sum(
                1 for t in processed_data["templates"] if t["vulnerabilities"]
            )
            
            # Count vulnerabilities by type
            for vuln_type in processed_data["vulnerabilities"]:
                processed_data["summary"]["vulnerability_counts"][vuln_type] = len(
                    processed_data["vulnerabilities"][vuln_type]
                )
        
        return processed_data
    
    def get_adcs_servers(self, as_json: bool = True) -> Union[str, List]:
        """
        Find all ADCS servers in the domain using LDAP.
        
        Args:
            as_json (bool): Whether to return results as JSON string or list
            
        Returns:
            Union[str, List]: JSON string or list containing ADCS servers
        """
        adcs_logger.info("Querying for ADCS servers in the domain")
        
        # LDAP filter to find ADCS servers
        ldap_filter = "(&(objectCategory=pKIEnrollmentService))"
        attributes = ["dNSHostName", "name", "cACertificate", "certificateTemplates"]
        
        try:
            results = self.ldap.query(ldapfilter=ldap_filter, attributes=attributes, as_json=False)
            
            adcs_servers = []
            for result in results:
                server_info = {
                    "hostname": result["attributes"].get("dNSHostName", [""])[0],
                    "name": result["attributes"].get("name", [""])[0],
                    "templates": result["attributes"].get("certificateTemplates", [])
                }
                adcs_servers.append(server_info)
            
            adcs_logger.debug(f"Found {len(adcs_servers)} ADCS servers")
            return json.dumps(adcs_servers) if as_json else adcs_servers
            
        except Exception as e:
            adcs_logger.exception(f"Error querying for ADCS servers: {str(e)}")
            error_data = {
                "error": True,
                "message": str(e),
                "query": "ADCS servers",
                "status": "exception"
            }
            return json.dumps(error_data) if as_json else error_data