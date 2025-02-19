from sys import exit, _getframe
from ssl import CERT_NONE
from ldap3 import (
    Server,
    Connection,
    SASL,
    KERBEROS,
    NTLM,
    SUBTREE,
    ALL as LDAP3_ALL,
    BASE,
    DEREF_NEVER,
    TLS_CHANNEL_BINDING,
    ENCRYPT,
    MODIFY_REPLACE,
)
from ldap3 import SIMPLE
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.core.exceptions import (
    LDAPOperationResult,
    LDAPSocketOpenError,
    LDAPAttributeError,
    LDAPSocketSendError,
)
from ldap3.extend.microsoft.unlockAccount import ad_unlock_account
from ldap3.extend.microsoft.modifyPassword import ad_modify_password
from ldap3.extend.microsoft.addMembersToGroups import (
    ad_add_members_to_groups as addUsersInGroups,
)
from ldap3.extend.microsoft.removeMembersFromGroups import (
    ad_remove_members_from_groups as removeUsersInGroups,
)

from ldap3 import ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
import ldap3

ALL = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]

class LdapConnector():
    def __init__(self,
                server_string: str,
                domain: str = "",
                base: str = "",
                username: str = "",
                password: str = "",
                method: str = "NTLM",
                encryption: bool = False,
                ldapPort: int = 389,
                ldapsPort: int = 636,
                throttle=0,
                page_size=1000,):
        """
        LDAP Connector constructor will initialize the connection
        with the LDAP server.
        
        https://offsec.almond.consulting/ldap-authentication-in-active-directory-environments.html

        Authentication modes:
            * Simple: username/password
            * NTLM (username + NTLM hash/password)
            * Kerberos 

        Args:
            server_string (str): LDAP Server (ldap://...)
            domain (str): Fully qualified domain name of the Active Directory domain.
            base (str): Base for the LDAP queries.
            username (str): AD username
            password (str): AD password
            method (str): Either to use NTLM, SIMPLE, Kerberos or anonymous authentication. 
            encryption (bool): Use Encrypted Communication
        
        Returns:
            list: a list of strings representing the header columns
        """
        self.domain = domain
        self.server_string = server_string
        self.base = base
        self.username = username
        self.password = password
        self.encryption = encryption
        self.throttle = throttle
        self.page_size = page_size
        self.method = method

        self.ldapPort = ldapPort
        self.ldapsPort = ldapsPort
        self.attributes = ALL
        self.controls = []

        self.createLDAPServerObj()
        self.createLDAPConnection()

        self.base_dn = base or self.server.info.other["defaultNamingContext"][0]
        self.fqdn = ".".join(
            map(
                lambda x: x.replace("DC=", ""),
                filter(lambda x: x.startwith("DC"), self.base_dn.split(",")),
            )
        )
        self.search_scope = SUBTREE


        
    def createLDAPServerObj(self):
        tls = ldap3.Tls(validate=CERT_NONE)

        if self.server_string.startswith("ldaps"):
            self.server = Server(
                self.server_string,
                port = self.ldapsPort,
                use_ssl = True,
                allowed_referral_hosts = [("*", True)],
                get_info = LDAP3_ALL,
                tls = tls,
            )
        
        else:
            self.server = Server(
                self.server_string,
                port = self.ldapPort,
                get_info = LDAP3_ALL
            )
    
    def createLDAPConnection(self):
        if self.method == "Kerberos":
            if self.server_string.startswith("ldaps"):
                self.ldap = Connection(
                    self.server,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS
                )
            else:
                if self.encryption:
                    self.ldap = Connection(
                        self.server,
                        authentication = SASL,
                        sasl_mechanism = KERBEROS,
                        session_security = ENCRYPT
                    )

                else:
                    self.ldap = Connection(
                        self.server,
                        authentication=SASL,
                        sasl_mechanism=KERBEROS,
                    )
                
        elif self.method == "anonymous":
            self.ldap = Connection(self.server)

        elif self.method == "NTLM":
            ntlm = self.password

            if self.server_string.startswith("ldaps"):
                if self.encryption:
                    self.ldap = Connection(
                        self.server,
                        user = f"{self.domain}\\{self.username}",
                        password = ntlm,
                        authentication = NTLM,
                        channel_binding = TLS_CHANNEL_BINDING,
                        check_names = True,
                    )
                else:
                    self.ldap = Connection(
                        self.server,
                        user = f"{self.domain}\\{self.username}",
                        password = ntlm,
                        authentication = NTLM,
                        check_names = True,
                    )

            else:
                if self.encryption:
                    self.ldap = Connection(
                        self.server,
                        user = f"{self.domain}\\{self.username}",
                        password = ntlm,
                        authentication = NTLM,
                        session_security=ENCRYPT,
                        check_names = True,
                    )

                else:
                    self.ldap = Connection(
                        self.server,
                        user = f"{self.domain}\\{self.username}",
                        password = ntlm,
                        authentication = NTLM,
                        check_names = True,
                    )
        elif self.method == "SIMPLE":
            if "." in self.domain:
                simple_domain, _, _ = self.domain.partition(".")
            
            self.ldap = Connection(
                self.server,
                user = f"{simple_domain}\\{self.username}",
                password = self.password,
                authentication = SIMPLE,
                check_names = True,
            )
        try:
            if not self.ldap.bind():
                print("I should log a binding error to the log file")
            if self.method == "anonymous":
                anon_base = self.ldap.request["base"].split(",")
                for i, item in enumerate(anon_base):
                    if item.startswith("DC="):
                        anon_base = ",".join(anon_base[i:])
                        break
                self.ldap.search(
                    search_base = anon_base,
                    search_filter = "(objectClass=*)",
                    search_scope = "SUBTREE",
                    attributes = "*",
                )

                if len(self.ldap.entries) == 0:
                    print("I should log no info retrieved as anon")
        except LDAPSocketOpenError:
            print(f"I should log that we are unable to open connection with {self.server_string}")
        except LDAPSocketSendError:
            print(f"I should log unable to open connection with {self.server_string}, maybe LDAPS is not enabled ")
    
    def ldapQueryResult(self, data):
        if "dn" in data:
            result = data["attributes"]
            result["dn"] = result["dn"]
            return dict(result)


    def query(self, ldapfilter: str, attributes=[], base=None, scope=None):
        """
        A method to perform a query to the LDAP server and return the results as a generator.
        
        Args:
            ldapfilter (str): The LDAP filter to query.
            attributes (list): List of attributes to retrieve with the query.
            base: Base to use during the request.
            scope: Scope to use during the request.

        Returns:
            A generator yielding records.
        """
        attributes = self.attributes if attributes == [] else attributes

        try:
            entry_generator = self.ldap.extend.standard.paged_search(
                search_base = base or self.base_dn,
                search_filter = ldapfilter,
                search_scope = scope or self.search_scope,
                attributes = attributes,
                controls = self.controls,
                paged_size = self.page_size,
                generator = True,
            )
        except LDAPOperationResult as e:
            print("I should log an error")
        except LDAPAttributeError as e:
            if not _getframe().f_back.f_code.co_name == "get_laps":
                print("I Should log some error")
        
        return filter(lambda x: x is not None, map(self.ldapQueryResult, entry_generator))

    pass
