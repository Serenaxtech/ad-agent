from ftp import FTPScanner
from ldap.ldap import LdapConnector

ldap_connect = LdapConnector("ldap://192.168.8.112", domain="adlab.local", username="ldapuser", password="UserPass1234!")

ftp_test_scanner = FTPScanner(ldap_connect)

servers = ftp_test_scanner.get_domain_servers()
print("[+] Retrieved Servers:", servers)

ftp_open = ftp_test_scanner.check_port_open("192.168.8.113")
print("[+] Open FTP:", ftp_open)

print(ftp_test_scanner.check_anonymous_access("192.168.8.113"))

print(ftp_test_scanner.check_ftp_vulnerabilities("192.168.8.113"))

print(ftp_test_scanner.scan_network_for_ftp())