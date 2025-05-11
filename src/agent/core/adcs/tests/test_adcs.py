import json
import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import logging

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from adcs.adcs import ADCSScanner

class MockLdapConnector:
    def __init__(self, base_dn="DC=example,DC=com"):
        self.base_dn = base_dn
    
    def query(self, ldapfilter, attributes, base=None, as_json=True):
        logging.info(f"MockLdapConnector.query called with filter: {ldapfilter}, attributes: {attributes}")
        
        if "pKIEnrollmentService" in ldapfilter:
            mock_adcs_servers = [
                {
                    "dn": "CN=CA01,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com",
                    "attributes": {
                        "dNSHostName": ["ca01.example.com"],
                        "name": ["Example-CA"],
                        "certificateTemplates": ["User", "Computer", "WebServer"]
                    }
                }
            ]
            return json.dumps(mock_adcs_servers) if as_json else mock_adcs_servers
        
        return json.dumps([]) if as_json else []

class TestADCSScanner(unittest.TestCase):
    @patch('subprocess.run')
    def setUp(self, mock_run):
        # Mock the certipy version check
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "certipy 1.0.0"
        mock_run.return_value = mock_process
        
        self.ldap_connector = MockLdapConnector()
        self.adcs_scanner = ADCSScanner(self.ldap_connector)
    
    @patch('subprocess.run')
    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data='{"domain": "example.com", "certificate_authorities": {"Example-CA": {"dns_name": "ca01.example.com", "ca_name": "Example-CA", "web_enrollment": true}}, "certificate_templates": {"WebServer": {"display_name": "Web Server", "vulnerabilities": ["ESC1"]}}}')
    def test_scan_vulnerable_templates(self, mock_open, mock_temp_file, mock_run):
        # Mock the temporary file
        mock_temp = MagicMock()
        mock_temp.name = "/tmp/certipy_output.json"
        mock_temp_file.return_value.__enter__.return_value = mock_temp
        
        # Mock the subprocess run
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "Certipy completed successfully"
        mock_run.return_value = mock_process
        
        # Call the method
        result = self.adcs_scanner.scan_vulnerable_templates(
            domain="example.com",
            username="testuser",
            password="testpass"
        )
        
        # Parse the result
        result_dict = json.loads(result)
        
        # Verify the result
        self.assertEqual(result_dict["domain"], "example.com")
        self.assertEqual(len(result_dict["cas"]), 1)
        self.assertEqual(result_dict["cas"][0]["name"], "Example-CA")
        self.assertEqual(len(result_dict["templates"]), 1)
        self.assertEqual(result_dict["templates"][0]["name"], "WebServer")
        self.assertEqual(result_dict["templates"][0]["vulnerabilities"], ["ESC1"])
        self.assertEqual(len(result_dict["vulnerabilities"]["esc1"]), 1)
        self.assertEqual(result_dict["vulnerabilities"]["esc1"][0], "WebServer")
    
    def test_get_adcs_servers(self):
        # Call the method
        result = self.adcs_scanner.get_adcs_servers()
        
        # Parse the result
        result_list = json.loads(result)
        
        # Verify the result
        self.assertEqual(len(result_list), 1)
        self.assertEqual(result_list[0]["hostname"], "ca01.example.com")
        self.assertEqual(result_list[0]["name"], "Example-CA")
        self.assertEqual(result_list[0]["templates"], ["User", "Computer", "WebServer"])

if __name__ == "__main__":
    unittest.main()