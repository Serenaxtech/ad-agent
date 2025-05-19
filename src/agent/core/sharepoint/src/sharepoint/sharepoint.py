import json
import logging
import re
import requests
import os
import tempfile
from typing import Dict, List, Optional, Any, Union
from urllib3.exceptions import InsecureRequestWarning

from ldap.ldap import LdapConnector
from config.config import Config
from logging_custom.logging_custom import configure_logging

# Disable warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

sharepoint_logger = logging.getLogger(__name__)

class SharepointScanner:
    """
    A module for scanning Sharepoint and Frontpage servers for security vulnerabilities.
    This module identifies security issues in Sharepoint and Frontpage installations.
    """
    
    def __init__(self, ldap_connector: Optional[LdapConnector] = None, custom_headers: Dict = None, custom_proxy: Dict = None):
        """
        Initialize the Sharepoint Scanner module.
        
        Args:
            ldap_connector (Optional[LdapConnector]): An initialized LDAP connector for AD queries
            custom_headers (Dict): Custom HTTP headers to use for requests
            custom_proxy (Dict): Custom proxy configuration for requests
        """
        self.ldap = ldap_connector
        self.custom_headers = custom_headers or {}
        self.custom_proxy = custom_proxy or {}
        
        # Frontend (bin) repository files
        self.front_bin = [
            '_vti_inf.html', '_vti_bin/shtml.dll/_vti_rpc', '_vti_bin/owssvr.dll', 
            '_vti_bin/_vti_adm/admin.dll', '_vti_bin/_vti_adm/admin.exe', 
            '_vti_bin/_vti_aut/author.exe', '_vti_bin/_vti_aut/WS_FTP.log',
            '_vti_bin/_vti_aut/ws_ftp.log', '_vti_bin/shtml.exe/_vti_rpc', 
            '_vti_bin/_vti_aut/author.dll'
        ]
        
        # Frontend services
        self.front_services = [
            '_vti_bin/Admin.asmx', '_vti_bin/alerts.asmx', '_vti_bin/dspsts.asmx', 
            '_vti_bin/forms.asmx', '_vti_bin/Lists.asmx', '_vti_bin/people.asmx', 
            '_vti_bin/Permissions.asmx', '_vti_bin/search.asmx', '_vti_bin/UserGroup.asmx', 
            '_vti_bin/versions.asmx', '_vti_bin/Views.asmx', '_vti_bin/webpartpages.asmx', 
            '_vti_bin/webs.asmx', '_vti_bin/spsdisco.aspx', '_vti_bin/AreaService.asmx', 
            '_vti_bin/BusinessDataCatalog.asmx', '_vti_bin/ExcelService.asmx',
            '_vti_bin/SharepointEmailWS.asmx', '_vti_bin/spscrawl.asmx', 
            '_vti_bin/spsearch.asmx', '_vti_bin/UserProfileService.asmx', 
            '_vti_bin/WebPartPages.asmx'
        ]
        
        # Frontend (pvt) repository files
        self.front_pvt = [
            '_vti_pvt/authors.pwd', '_vti_pvt/administrators.pwd', '_vti_pvt/users.pwd', 
            '_vti_pvt/service.pwd', '_vti_pvt/service.grp', '_vti_pvt/bots.cnf', 
            '_vti_pvt/service.cnf', '_vti_pvt/access.cnf', '_vti_pvt/writeto.cnf', 
            '_vti_pvt/botsinf.cnf', '_vti_pvt/doctodep.btr', '_vti_pvt/deptodoc.btr', 
            '_vti_pvt/linkinfo.cnf', '_vti_pvt/services.org', '_vti_pvt/structure.cnf', 
            '_vti_pvt/svcacl.cnf', '_vti_pvt/uniqperm.cnf', '_vti_pvt/service/lck', 
            '_vti_pvt/frontpg.lck'
        ]
        
        # Sharepoint and Frontend (directory) repository
        self.directory_check = [
            '_vti_pvt/', '_vti_bin/', '_vti_log/', '_vti_cnf/', '_vti_bot', 
            '_vti_bin/_vti_adm', '_vti_bin/_vti_aut', '_vti_txt/'
        ]
        
        # Sharepoint repository files - layout
        self.sharepoint_check_layout = [
            '_layouts/aclinv.aspx', '_layouts/addrole.aspx', '_layouts/AdminRecycleBin.aspx',
            '_layouts/AreaNavigationSettings.aspx', '_Layouts/AreaTemplateSettings.aspx',
            '_Layouts/AreaWelcomePage.aspx', '_layouts/associatedgroups.aspx', '_layouts/bpcf.aspx',
            '_Layouts/ChangeSiteMasterPage.aspx', '_layouts/create.aspx', '_layouts/editgrp.aspx',
            '_layouts/editprms.aspx', '_layouts/groups.aspx', '_layouts/help.aspx', 
            '_layouts/images/', '_layouts/listedit.aspx', '_layouts/ManageFeatures.aspx', 
            '_layouts/ManageFeatures.aspx', '_layouts/mcontent.aspx', '_layouts/mngctype.aspx', 
            '_layouts/mngfield.aspx', '_layouts/mngsiteadmin.aspx', '_layouts/mngsubwebs.aspx', 
            '_layouts/mngsubwebs.aspx?view=sites', '_layouts/mobile/mbllists.aspx', 
            '_layouts/MyInfo.aspx', '_layouts/MyPage.aspx', '_layouts/MyTasks.aspx',
            '_layouts/navoptions.aspx', '_layouts/NewDwp.aspx', '_layouts/newgrp.aspx',
            '_layouts/newsbweb.aspx', '_layouts/PageSettings.aspx', '_layouts/people.aspx',
            '_layouts/people.aspx?MembershipGroupId=0', '_layouts/permsetup.aspx',
            '_layouts/picker.aspx', '_layouts/policy.aspx', '_layouts/policyconfig.aspx',
            '_layouts/policycts.aspx', '_layouts/Policylist.aspx', '_layouts/prjsetng.aspx',
            '_layouts/quiklnch.aspx', '_layouts/recyclebin.aspx', '_Layouts/RedirectPage.aspx', 
            '_layouts/role.aspx', '_layouts/settings.aspx', '_layouts/SiteDirectorySettings.aspx', 
            '_layouts/sitemanager.aspx', '_layouts/SiteManager.aspx?lro=all', '_layouts/spcf.aspx', 
            '_layouts/storman.aspx', '_layouts/themeweb.aspx', '_layouts/topnav.aspx', 
            '_layouts/user.aspx', '_layouts/userdisp.aspx', '_layouts/userdisp.aspx?ID=1', 
            '_layouts/useredit.aspx', '_layouts/useredit.aspx?ID=1', 
            '_layouts/viewgrouppermissions.aspx', '_layouts/viewlsts.aspx', '_layouts/vsubwebs.aspx', 
            '_layouts/WPPrevw.aspx?ID=247', '_layouts/wrkmng.aspx'
        ]
        
        # Sharepoint repository files - forms
        self.sharepoint_check_forms = [
            'Forms/DispForm.aspx', 'Forms/DispForm.aspx?ID=1', 'Forms/EditForm.aspx',
            'Forms/EditForm.aspx?ID=1', 'Forms/Forms/AllItems.aspx', 'Forms/MyItems.aspx',
            'Forms/NewForm.aspx', 'Pages/default.aspx', 'Pages/Forms/AllItems.aspx'
        ]
        
        # Sharepoint repository files - catalog
        self.sharepoint_check_catalog = [
            '_catalogs/masterpage/Forms/AllItems.aspx', '_catalogs/wp/Forms/AllItems.aspx',
            '_catalogs/wt/Forms/Common.aspx'
        ]
        
        configure_logging(sharepoint_logger, "sharepoint-module")
        sharepoint_logger.info("Sharepoint Scanner module initialized")
    
    def get_target_information(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Get basic information about the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing target information
        """
        sharepoint_logger.info(f"Getting information for target: {target_url}")
        
        result = {
            "url": target_url,
            "status_code": None,
            "server": None,
            "headers": {},
            "error": None
        }
        
        try:
            response = requests.get(target_url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
            result["status_code"] = response.status_code
            result["headers"] = dict(response.headers)
            
            if "server" in response.headers:
                result["server"] = response.headers["server"]
                
            sharepoint_logger.debug(f"Target responded with status code: {response.status_code}")
            
        except Exception as e:
            sharepoint_logger.exception(f"Error getting target information: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def scan_frontpage_directories(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan for Frontpage directories on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        sharepoint_logger.info(f"Scanning Frontpage directories on: {target_url}")
        
        result = {
            "target": target_url,
            "directories_checked": len(self.directory_check),
            "directories_found": 0,
            "found_directories": [],
            "error": None
        }
        
        try:
            for directory in self.directory_check:
                url = f"{target_url}/{directory}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200 or response.status_code == 401:  # 401 means it exists but requires auth
                        result["directories_found"] += 1
                        result["found_directories"].append({
                            "url": url,
                            "status_code": response.status_code
                        })
                        sharepoint_logger.debug(f"Found directory: {url} (Status: {response.status_code})")
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking directory {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error scanning Frontpage directories: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def scan_frontpage_bin_files(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan for Frontpage bin files on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        sharepoint_logger.info(f"Scanning Frontpage bin files on: {target_url}")
        
        result = {
            "target": target_url,
            "files_checked": len(self.front_bin),
            "files_found": 0,
            "found_files": [],
            "error": None
        }
        
        try:
            for file in self.front_bin:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200 or response.status_code == 401:
                        result["files_found"] += 1
                        result["found_files"].append({
                            "url": url,
                            "status_code": response.status_code
                        })
                        sharepoint_logger.debug(f"Found bin file: {url} (Status: {response.status_code})")
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking bin file {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error scanning Frontpage bin files: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def scan_frontpage_pvt_files(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan for Frontpage private files on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        sharepoint_logger.info(f"Scanning Frontpage private files on: {target_url}")
        
        result = {
            "target": target_url,
            "files_checked": len(self.front_pvt),
            "files_found": 0,
            "found_files": [],
            "error": None
        }
        
        try:
            for file in self.front_pvt:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200 or response.status_code == 401:
                        result["files_found"] += 1
                        result["found_files"].append({
                            "url": url,
                            "status_code": response.status_code,
                            "content": response.text if response.status_code == 200 else None
                        })
                        sharepoint_logger.debug(f"Found private file: {url} (Status: {response.status_code})")
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking private file {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error scanning Frontpage private files: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def dump_credentials(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Attempt to dump credentials from Frontpage private files.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing dumped credentials
        """
        sharepoint_logger.info(f"Attempting to dump credentials from: {target_url}")
        
        result = {
            "target": target_url,
            "files_checked": 0,
            "credentials_found": False,
            "credential_files": [],
            "error": None
        }
        
        pwd_files = ['_vti_pvt/service.pwd', '_vti_pvt/administrators.pwd', '_vti_pvt/authors.pwd']
        result["files_checked"] = len(pwd_files)
        
        try:
            for file in pwd_files:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200:
                        result["credentials_found"] = True
                        result["credential_files"].append({
                            "file": file,
                            "url": url,
                            "content": response.text
                        })
                        sharepoint_logger.debug(f"Found credential file: {url}")
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking credential file {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error dumping credentials: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def fingerprint_frontpage(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Fingerprint the Frontpage version on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing fingerprint results
        """
        sharepoint_logger.info(f"Fingerprinting Frontpage on: {target_url}")
        
        result = {
            "target": target_url,
            "is_frontpage": False,
            "platform": None,  # "windows" or "nix"
            "version": None,
            "files_found": [],
            "error": None
        }
        
        # Check for Windows version files
        enum_win = [
            '_vti_bin/_vti_aut/author.dll', 
            '_vti_bin/_vti_aut/dvwssr.dll', 
            '_vti_bin/_vti_adm/admin.dll',
            '_vti_bin/shtml.dll'
        ]
        
        # Check for *nix version files
        enum_nix = [
            '_vti_bin/_vti_aut/author.exe', 
            '_vti_bin/_vti_adm/admin.exe', 
            '_vti_bin/shtml.exe'
        ]
        
        try:
            # Check Windows files
            for file in enum_win:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200:
                        result["is_frontpage"] = True
                        result["platform"] = "windows"
                        result["files_found"].append({
                            "file": file,
                            "url": url,
                            "status_code": response.status_code
                        })
                except Exception:
                    continue
            
            # Check *nix files
            for file in enum_nix:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200:
                        result["is_frontpage"] = True
                        result["platform"] = "nix"
                        result["files_found"].append({
                            "file": file,
                            "url": url,
                            "status_code": response.status_code
                        })
                except Exception:
                    continue
            
            # Get version from _vti_inf.html
            version_url = f"{target_url}/_vti_inf.html"
            try:
                response = requests.get(version_url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                if response.status_code == 200:
                    result["is_frontpage"] = True
                    version_match = re.findall(r'FPVersion=(.*)', response.text)
                    if version_match:
                        result["version"] = version_match[0]
                    result["files_found"].append({
                        "file": "_vti_inf.html",
                        "url": version_url,
                        "status_code": response.status_code
                    })
            except Exception as e:
                sharepoint_logger.debug(f"Error checking version file: {str(e)}")
                
        except Exception as e:
            sharepoint_logger.exception(f"Error fingerprinting Frontpage: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def check_frontpage_rpc(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Check if Frontpage RPC is available on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing RPC check results
        """
        sharepoint_logger.info(f"Checking Frontpage RPC on: {target_url}")
        
        result = {
            "target": target_url,
            "rpc_available": False,
            "rpc_endpoints": [],
            "server_version": None,
            "error": None
        }
        
        # RPC endpoints to check
        rpc_endpoints = ['_vti_bin/shtml.exe/_vti_rpc', '_vti_bin/shtml.dll/_vti_rpc']
        
        # Custom headers for RPC check
        local_headers = {
            'MIME-Version': '4.0',
            'User-Agent': 'MSFrontPage/4.0',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Connection': 'Keep-Alive'
        }
        local_headers.update(self.custom_headers)
        
        try:
            for endpoint in rpc_endpoints:
                url = f"{target_url}/{endpoint}"
                try:
                    # First check with GET
                    response = requests.get(url, verify=False, headers=local_headers, proxies=self.custom_proxy)
                    if response.status_code == 200:
                        result["rpc_available"] = True
                        result["rpc_endpoints"].append({
                            "endpoint": endpoint,
                            "url": url,
                            "method": "GET",
                            "status_code": response.status_code
                        })
                        
                        # Then try POST to get version
                        data = ["method=server version"]
                        post_response = requests.post(url, json=data, headers=local_headers, verify=False, proxies=self.custom_proxy)
                        if post_response.status_code == 200:
                            result["server_version"] = post_response.text
                            result["rpc_endpoints"].append({
                                "endpoint": endpoint,
                                "url": url,
                                "method": "POST",
                                "status_code": post_response.status_code
                            })
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking RPC endpoint {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error checking Frontpage RPC: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def scan_sharepoint_layouts(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan for Sharepoint layout files on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        sharepoint_logger.info(f"Scanning Sharepoint layout files on: {target_url}")
        
        result = {
            "target": target_url,
            "files_checked": len(self.sharepoint_check_layout),
            "files_found": 0,
            "found_files": [],
            "error": None
        }
        
        try:
            for file in self.sharepoint_check_layout:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200 or response.status_code == 401:
                        result["files_found"] += 1
                        result["found_files"].append({
                            "url": url,
                            "status_code": response.status_code
                        })
                        sharepoint_logger.debug(f"Found layout file: {url} (Status: {response.status_code})")
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking layout file {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error scanning Sharepoint layout files: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def scan_sharepoint_forms(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan for Sharepoint form files on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        sharepoint_logger.info(f"Scanning Sharepoint form files on: {target_url}")
        
        result = {
            "target": target_url,
            "files_checked": len(self.sharepoint_check_forms),
            "files_found": 0,
            "found_files": [],
            "error": None
        }
        
        try:
            for file in self.sharepoint_check_forms:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200 or response.status_code == 401:
                        result["files_found"] += 1
                        result["found_files"].append({
                            "url": url,
                            "status_code": response.status_code
                        })
                        sharepoint_logger.debug(f"Found form file: {url} (Status: {response.status_code})")
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking form file {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error scanning Sharepoint form files: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def scan_sharepoint_catalogs(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan for Sharepoint catalog files on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        sharepoint_logger.info(f"Scanning Sharepoint catalog files on: {target_url}")
        
        result = {
            "target": target_url,
            "files_checked": len(self.sharepoint_check_catalog),
            "files_found": 0,
            "found_files": [],
            "error": None
        }
        
        try:
            for file in self.sharepoint_check_catalog:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200 or response.status_code == 401:
                        result["files_found"] += 1
                        result["found_files"].append({
                            "url": url,
                            "status_code": response.status_code
                        })
                        sharepoint_logger.debug(f"Found catalog file: {url} (Status: {response.status_code})")
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking catalog file {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error scanning Sharepoint catalog files: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def check_sharepoint_version(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Attempt to determine the Sharepoint version of the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing version information
        """
        sharepoint_logger.info(f"Checking Sharepoint version on: {target_url}")
        
        result = {
            "target": target_url,
            "is_sharepoint": False,
            "version": None,
            "build": None,
            "version_details": None,
            "error": None
        }
        
        # Version detection files
        version_files = [
            '_vti_inf.html',
            '_layouts/versioninfo.aspx',
            '_layouts/15/versioninfo.aspx',
            '_layouts/16/versioninfo.aspx'
        ]
        
        try:
            # First check server headers
            try:
                response = requests.get(target_url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                if "microsoftsharepointteamservices" in response.headers:
                    result["is_sharepoint"] = True
                    result["version"] = response.headers["microsoftsharepointteamservices"]
                    
                    # Map version number to product name
                    version_map = {
                        "12.": "SharePoint 2007",
                        "14.": "SharePoint 2010",
                        "15.": "SharePoint 2013",
                        "16.": "SharePoint 2016/2019/Online"
                    }
                    
                    for prefix, name in version_map.items():
                        if result["version"].startswith(prefix):
                            result["version_details"] = name
                            break
            except Exception as e:
                sharepoint_logger.debug(f"Error checking server headers: {str(e)}")
            
            # Check version files
            for file in version_files:
                url = f"{target_url}/{file}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200:
                        result["is_sharepoint"] = True
                        
                        # Try to extract version from content
                        if file == '_vti_inf.html':
                            version_match = re.findall(r'FPVersion=(.*)', response.text)
                            if version_match:
                                result["build"] = version_match[0]
                        
                        # For versioninfo.aspx pages, extract from HTML
                        elif 'versioninfo.aspx' in file:
                            # Simple regex to find version numbers in the HTML
                            version_match = re.findall(r'Version: ([0-9.]+)', response.text)
                            if version_match:
                                result["build"] = version_match[0]
                                
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking version file {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error checking Sharepoint version: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def scan_sharepoint_services(self, target_url: str, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan for Sharepoint web services on the target server.
        
        Args:
            target_url (str): The URL of the target server
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        sharepoint_logger.info(f"Scanning Sharepoint web services on: {target_url}")
        
        result = {
            "target": target_url,
            "services_checked": len(self.front_services),
            "services_found": 0,
            "found_services": [],
            "error": None
        }
        
        try:
            for service in self.front_services:
                url = f"{target_url}/{service}"
                try:
                    response = requests.get(url, verify=False, headers=self.custom_headers, proxies=self.custom_proxy)
                    if response.status_code == 200 or response.status_code == 401:
                        result["services_found"] += 1
                        result["found_services"].append({
                            "service": service,
                            "url": url,
                            "status_code": response.status_code
                        })
                        sharepoint_logger.debug(f"Found service: {url} (Status: {response.status_code})")
                except Exception as e:
                    sharepoint_logger.debug(f"Error checking service {url}: {str(e)}")
                    continue
                    
        except Exception as e:
            sharepoint_logger.exception(f"Error scanning Sharepoint services: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def get_sharepoint_servers_from_ldap(self, as_json: bool = True) -> Union[str, List, Dict]:
        """
        Get a list of potential Sharepoint servers from LDAP.
        
        Args:
            as_json (bool): Whether to return results as JSON string or list/dict
            
        Returns:
            Union[str, List, Dict]: JSON string or list/dict containing potential Sharepoint servers
        """
        sharepoint_logger.info("Getting potential Sharepoint servers from LDAP")
        
        if not self.ldap:
            error_msg = "LDAP connector not initialized"
            sharepoint_logger.error(error_msg)
            error_data = {
                "error": True,
                "message": error_msg
            }
            return json.dumps(error_data) if as_json else error_data
        
        result = {
            "servers": [],
            "count": 0,
            "error": None
        }
        
        try:
            # Search for servers with common Sharepoint attributes
            search_filters = [
                "(servicePrincipalName=HTTP*)",
                "(servicePrincipalName=SharePoint*)",
                "(description=*SharePoint*)",
                "(description=*Web Server*)"
            ]
            
            servers = set()
            
            for search_filter in search_filters:
                try:
                    computers = self.ldap.search_computers(search_filter)
                    for computer in computers:
                        if "dNSHostName" in computer:
                            hostname = computer["dNSHostName"][0]
                            if hostname not in servers:
                                servers.add(hostname)
                                result["servers"].append({
                                    "hostname": hostname,
                                    "dns_name": hostname,
                                    "operating_system": computer.get("operatingSystem", ["Unknown"])[0],
                                    "description": computer.get("description", [""])[0]
                                })
                except Exception as e:
                    sharepoint_logger.debug(f"Error searching with filter {search_filter}: {str(e)}")
                    continue
            
            result["count"] = len(result["servers"])
            sharepoint_logger.info(f"Found {result['count']} potential Sharepoint servers")
            
        except Exception as e:
            sharepoint_logger.exception(f"Error getting Sharepoint servers from LDAP: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result
    
    def scan_all_servers(self, as_json: bool = True) -> Union[str, Dict]:
        """
        Scan all potential Sharepoint servers found in the domain.
        
        Args:
            as_json (bool): Whether to return results as JSON string or dict
            
        Returns:
            Union[str, Dict]: JSON string or dict containing scan results
        """
        sharepoint_logger.info("Starting scan of all potential Sharepoint servers")
        
        result = {
            "scan_timestamp": None,
            "servers_scanned": 0,
            "sharepoint_servers_found": 0,
            "frontpage_servers_found": 0,
            "servers": [],
            "error": None
        }
        
        try:
            # Get timestamp
            from datetime import datetime
            result["scan_timestamp"] = datetime.now().isoformat()
            
            # Get servers from LDAP
            servers_data = self.get_sharepoint_servers_from_ldap(as_json=False)
            
            if "error" in servers_data and servers_data["error"]:
                result["error"] = servers_data["error"]
                return json.dumps(result) if as_json else result
            
            servers = servers_data.get("servers", [])
            result["servers_scanned"] = len(servers)
            
            # Scan each server
            for server in servers:
                hostname = server["hostname"]
                server_result = {
                    "hostname": hostname,
                    "is_sharepoint": False,
                    "is_frontpage": False,
                    "version": None,
                    "vulnerabilities": [],
                    "scan_details": {}
                }
                
                # Try both http and https
                for protocol in ["http", "https"]:
                    target_url = f"{protocol}://{hostname}"
                    
                    try:
                        # Get basic information
                        info = self.get_target_information(target_url, as_json=False)
                        
                        if "error" in info and info["error"]:
                            continue
                        
                        # Check if it's Sharepoint
                        version_info = self.check_sharepoint_version(target_url, as_json=False)
                        if version_info["is_sharepoint"]:
                            server_result["is_sharepoint"] = True
                            server_result["version"] = version_info["version_details"] or version_info["version"]
                            result["sharepoint_servers_found"] += 1
                            
                            # Add scan details
                            server_result["scan_details"]["version_info"] = version_info
                            server_result["scan_details"]["layouts"] = self.scan_sharepoint_layouts(target_url, as_json=False)
                            server_result["scan_details"]["forms"] = self.scan_sharepoint_forms(target_url, as_json=False)
                            server_result["scan_details"]["catalogs"] = self.scan_sharepoint_catalogs(target_url, as_json=False)
                            server_result["scan_details"]["services"] = self.scan_sharepoint_services(target_url, as_json=False)
                            
                            # Check for vulnerabilities
                            if server_result["scan_details"]["services"]["services_found"] > 0:
                                server_result["vulnerabilities"].append({
                                    "type": "exposed_services",
                                    "severity": "medium",
                                    "description": f"Exposed {server_result['scan_details']['services']['services_found']} Sharepoint web services"
                                })
                        
                        # Check if it's Frontpage
                        fp_info = self.fingerprint_frontpage(target_url, as_json=False)
                        if fp_info["is_frontpage"]:
                            server_result["is_frontpage"] = True
                            if not server_result["version"]:
                                server_result["version"] = f"FrontPage {fp_info['version']}"
                            result["frontpage_servers_found"] += 1
                            
                            # Add scan details
                            server_result["scan_details"]["frontpage_info"] = fp_info
                            server_result["scan_details"]["directories"] = self.scan_frontpage_directories(target_url, as_json=False)
                            server_result["scan_details"]["bin_files"] = self.scan_frontpage_bin_files(target_url, as_json=False)
                            server_result["scan_details"]["pvt_files"] = self.scan_frontpage_pvt_files(target_url, as_json=False)
                            server_result["scan_details"]["rpc"] = self.check_frontpage_rpc(target_url, as_json=False)
                            
                            # Check for credentials
                            creds = self.dump_credentials(target_url, as_json=False)
                            server_result["scan_details"]["credentials"] = creds
                            
                            # Check for vulnerabilities
                            if creds["credentials_found"]:
                                server_result["vulnerabilities"].append({
                                    "type": "exposed_credentials",
                                    "severity": "critical",
                                    "description": "Exposed FrontPage credential files"
                                })
                            
                            if server_result["scan_details"]["rpc"]["rpc_available"]:
                                server_result["vulnerabilities"].append({
                                    "type": "rpc_exposed",
                                    "severity": "high",
                                    "description": "FrontPage RPC interface exposed"
                                })
                        
                        # If we found something, add to results and break the protocol loop
                        if server_result["is_sharepoint"] or server_result["is_frontpage"]:
                            server_result["url"] = target_url
                            break
                            
                    except Exception as e:
                        sharepoint_logger.debug(f"Error scanning {target_url}: {str(e)}")
                        continue
                
                # Add server to results if it's Sharepoint or Frontpage
                if server_result["is_sharepoint"] or server_result["is_frontpage"]:
                    result["servers"].append(server_result)
            
        except Exception as e:
            sharepoint_logger.exception(f"Error scanning all servers: {str(e)}")
            result["error"] = str(e)
        
        return json.dumps(result) if as_json else result