import json
import logging
from typing import List, Optional, Any 


from kerberos import Kerberos
from ldap.ldap import LdapConnector
from config.config import Config
from logging_custom.logging_custom import configure_logging

# Placeholder for Config class (if not importing a real one for testing)
class MockConfig(Config): # Inheriting from Config if it has base methods/attrs needed
    def __init__(self):
        # Initialize any base Config attributes if necessary
        # For example, if Config.__init__ takes arguments or sets up properties:
        # super().__init__(some_default_path_or_args) 
        # Or, if Config is simple, just pass or define mock attributes.
        # This example assumes Config can be instantiated without args or has a simple structure.
        pass

# Placeholder for LdapConnector class (if you want to mock LDAP interactions)
class MockLdapConnector:
    def __init__(self, server_string: str, domain: str, base: str, username: str, password: str, method: str, encryption: bool = False, ldapPort: int = 389, ldapsPort: int = 636, throttle=0, page_size=1000):
        self.base_dn = base
        # Use the imported kerberos_logger or a new one for the mock
        logging.info(f"MockLdapConnector initialized with base_dn: {self.base_dn}")

    def query(self, ldapfilter: str, attributes: List[str], base: Optional[str] = None, as_json: bool = True) -> Any:
        logging.info(f"MockLdapConnector.query called with filter: {ldapfilter}, attributes: {attributes}, base: {base}, as_json: {as_json}")
        if "msDS-SupportedEncryptionTypes" in attributes:
            return json.dumps([{"dn": f"DC=example,DC=com", "attributes": {"msDS-SupportedEncryptionTypes": [28]}}]) if as_json else [{"dn": f"DC=example,DC=com", "attributes": {"msDS-SupportedEncryptionTypes": [28]}}]
        
        dummy_entry = {
            "dn": f"CN=TestUser,OU=Users,{self.base_dn}",
            "attributes": {attr: f"dummy_{attr}_value" for attr in attributes}
        }
        if "objectClass" in attributes:
            dummy_entry["attributes"]["objectClass"] = ["top", "person", "organizationalPerson", "user"]
        return json.dumps([dummy_entry]) if as_json else [dummy_entry]

if __name__ == "__main__":
    print("--- Testing Kerberos Module ---")
    
    # Configure logging for the test (using the imported kerberos_logger)
    # The second argument to configure_logging is usually a log file name or identifier.
    # configure_logging(kerberos_logger, "kerberos-module-test") 
    
    # Use MockConfig
    mock_config = MockConfig()

    # Option 1: Use the actual LdapConnector (as in your original test block)
    # This makes it more of an integration test for LdapConnector as well.
    # Ensure your LDAP server is accessible with these credentials for this to work.
    actual_ldap_connector = LdapConnector(
        server_string="ldap://192.168.8.110", # Replace with your test DC
        domain="adlab.local",                # Replace with your test domain
        base="DC=adlab,DC=local",            # Replace with your test base DN
        username="ldapuser",                 # Replace with your test username
        password="UserPass1234!",            # Replace with your test password
        method="NTLM",
        # encryption, ldapPort, ldapsPort will use defaults from LdapConnector
    )
    
    # Option 2: Use MockLdapConnector for more controlled unit testing
    # mock_ldap_for_test = MockLdapConnector(
    #     server_string="ldap://mockdc.example.com",
    #     domain="example.com",
    #     base="DC=example,DC=com",
    #     username="testuser",
    #     password="testpassword",
    #     method="NTLM"
    # )

    # Choose which connector to use for the test:
    # For this example, I'm using the actual_ldap_connector as per your original script's behavior.
    # If you want to use the mock, change 'actual_ldap_connector' to 'mock_ldap_for_test' below.
    ldap_to_use = actual_ldap_connector 
    # ldap_to_use = mock_ldap_for_test # Uncomment this line and comment the one above to use the mock

    kerberos_checker = Kerberos(ldap_connector=ldap_to_use)

    print("\n[+] Testing getKerberoastableUsers...")
    kerberoastable_users = kerberos_checker.getKerberoastableUsers()
    print(json.dumps(json.loads(kerberoastable_users), indent=2) if isinstance(kerberoastable_users, str) else kerberoastable_users)

    print("\n[+] Testing getASREPRoastableUsers...")
    asrep_roastable_users = kerberos_checker.getASREPRoastableUsers()
    print(json.dumps(json.loads(asrep_roastable_users), indent=2) if isinstance(asrep_roastable_users, str) else asrep_roastable_users)

    print("\n[+] Testing getDomainEncryptionPolicies...")
    domain_policies = kerberos_checker.getDomainEncryptionPolicies()
    print(json.dumps(json.loads(domain_policies), indent=2) if isinstance(domain_policies, str) else domain_policies)

    print("\n[+] Testing getUnconstrainedDelegation...")
    unconstrained_delegation = kerberos_checker.getUnconstrainedDelegation()
    print(json.dumps(json.loads(unconstrained_delegation), indent=2) if isinstance(unconstrained_delegation, str) else unconstrained_delegation)

    print("\n[+] Testing getConstrainedDelegation...")
    constrained_delegation = kerberos_checker.getConstrainedDelegation()
    print(json.dumps(json.loads(constrained_delegation), indent=2) if isinstance(constrained_delegation, str) else constrained_delegation)

    print("\n[+] Testing getResourceBasedConstrainedDelegation...")
    rbcd = kerberos_checker.getResourceBasedConstrainedDelegation()
    print(json.dumps(json.loads(rbcd), indent=2) if isinstance(rbcd, str) else rbcd)

    print("\n--- Kerberos Module Test Complete ---")