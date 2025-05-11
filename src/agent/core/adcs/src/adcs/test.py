from adcs import ADCSScanner
from ldap.ldap import LdapConnector

ldap_connect = LdapConnector("ldap://192.168.8.110", domain="adlab.local", username="ldapuser", password="UserPass1234!")

# Initialize with credentials
scanner = ADCSScanner(
    ldap_connector=ldap_conn
)

# Call without providing credentials again
results = scanner.scan_vulnerable_templates(
    domain="adlab.local",
    username="ldapuser",
    password="UserPass1234!",
    as_json=True)