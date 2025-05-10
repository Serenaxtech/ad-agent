import json
import logging
from types import MethodType
from typing import List, Optional, Iterable, Dict, Any
from ldap.ldap import LdapConnector
from config.config import Config
from logging_custom.logging_custom import configure_logging

kerberos_logger = logging.getLogger(__name__)

class Kerberos:
    def __init__(self, ldap_connector: LdapConnector):
        self.ldap = ldap_connector
        configure_logging(kerberos_logger, "kerberos-module")
        kerberos_logger.info("Kerberos module initialized")

    def getKerberoastableUsers(self, as_json=True):
        """
        Retrieves user accounts that are potentially kerberoastable.
        These are enabled user accounts with a Service Principal Name (SPN) set.
        LDAP Filter: (&(samAccountType=805306368)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
        Attributes: sAMAccountName, servicePrincipalName, pwdLastSet, lastLogon, memberOf, description
        """
        ldap_filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        attributes = ["sAMAccountName", "servicePrincipalName", "pwdLastSet", "lastLogon", "memberOf", "description"]
        kerberos_logger.debug(f"Querying for Kerberoastable users with filter: {ldap_filter}")
        return self.ldap.query(ldapfilter=ldap_filter, attributes=attributes, as_json=as_json)

    def getASREPRoastableUsers(self, as_json=True):
        """
        Retrieves user accounts that are vulnerable to AS-REP roasting.
        These are enabled user accounts that have 'Do not require Kerberos preauthentication' set.
        LDAP Filter: (&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
        Attributes: sAMAccountName, userAccountControl, pwdLastSet, lastLogon
        """
        ldap_filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        attributes = ["sAMAccountName", "userAccountControl", "pwdLastSet", "lastLogon"]
        kerberos_logger.debug(f"Querying for AS-REP Roasting users with filter: {ldap_filter}")
        return self.ldap.query(ldapfilter=ldap_filter, attributes=attributes, as_json=as_json)

    def getDomainEncryptionPolicies(self, as_json=True):
        """
        Retrieves the Kerberos encryption types supported by the domain.
        Queries the domain object for msDS-SupportedEncryptionTypes.
        LDAP Filter: (objectClass=domain)
        Attributes: msDS-SupportedEncryptionTypes, distinguishedName
        """
        ldap_filter = "(objectClass=domain)"
        attributes = ["msDS-SupportedEncryptionTypes", "distinguishedName"]
        kerberos_logger.debug(f"Querying for Domain Encryption Policies with filter: {ldap_filter}")
        return self.ldap.query(ldapfilter=ldap_filter, attributes=attributes, base=self.ldap.base_dn, as_json=as_json)

    def getUnconstrainedDelegation(self, as_json=True):
        """
        Retrieves accounts (users or computers) configured for unconstrained delegation.
        LDAP Filter: (&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(objectClass=user)(objectClass=computer)))
        Attributes: sAMAccountName, userAccountControl, servicePrincipalName, dNSHostName, objectClass
        """
        ldap_filter = "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(objectClass=user)(objectClass=computer)))"
        attributes = ["sAMAccountName", "userAccountControl", "servicePrincipalName", "dNSHostName", "objectClass"]
        kerberos_logger.debug(f"Querying for Unconstrained Delegation accounts with filter: {ldap_filter}")
        return self.ldap.query(ldapfilter=ldap_filter, attributes=attributes, as_json=as_json)

    def getConstrainedDelegation(self, as_json=True):
        """
        Retrieves accounts (users or computers) configured for traditional constrained delegation.
        These accounts have the msDS-AllowedToDelegateTo attribute set.
        LDAP Filter: (&(msDS-AllowedToDelegateTo=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(objectClass=user)(objectClass=computer)))
        Attributes: sAMAccountName, msDS-AllowedToDelegateTo, userAccountControl, objectClass
        """
        ldap_filter = "(&(msDS-AllowedToDelegateTo=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(objectClass=user)(objectClass=computer)))"
        attributes = ["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl", "objectClass"]
        kerberos_logger.debug(f"Querying for Constrained Delegation accounts with filter: {ldap_filter}")
        return self.ldap.query(ldapfilter=ldap_filter, attributes=attributes, as_json=as_json)

    def getResourceBasedConstrainedDelegation(self, as_json=True):
        """
        Retrieves accounts (typically computers or services) that are targets of
        Resource-Based Constrained Delegation (RBCD).
        These accounts have the msDS-AllowedToActOnBehalfOfOtherIdentity attribute set.
        LDAP Filter: (msDS-AllowedToActOnBehalfOfOtherIdentity=*)
        Attributes: sAMAccountName, dNSHostName, msDS-AllowedToActOnBehalfOfOtherIdentity, objectClass
        """
        ldap_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
        attributes = ["sAMAccountName", "dNSHostName", "msDS-AllowedToActOnBehalfOfOtherIdentity", "objectClass"]
        kerberos_logger.debug(f"Querying for Resource-Based Constrained Delegation targets with filter: {ldap_filter}")
        return self.ldap.query(ldapfilter=ldap_filter, attributes=attributes, as_json=as_json)

    def run_all_scans(self, as_json=True) -> Dict[str, Any]:
        """
        Runs all available Kerberos-related scans and returns combined results.
        
        Args:
            as_json (bool): Whether to return results as a JSON string or dictionary
            
        Returns:
            Dict or str: Combined results from all scans, either as a dictionary or JSON string
        """
        kerberos_logger.info("Starting comprehensive Kerberos scan")
        
        scan_results = {
            "kerberoastable_users": json.loads(self.getKerberoastableUsers(as_json=True)),
            "asreproast_users": json.loads(self.getASREPRoastableUsers(as_json=True)),
            "domain_encryption": json.loads(self.getDomainEncryptionPolicies(as_json=True)),
            "unconstrained_delegation": json.loads(self.getUnconstrainedDelegation(as_json=True)),
            "constrained_delegation": json.loads(self.getConstrainedDelegation(as_json=True)),
            "resource_based_constrained_delegation": json.loads(self.getResourceBasedConstrainedDelegation(as_json=True))
        }
        
        kerberos_logger.info("Completed comprehensive Kerberos scan")
        
        if as_json:
            return json.dumps(scan_results)
        return scan_results
