import json
import logging
from types import MethodType
from typing import List, Optional, Iterable, Dict, Any
from ldapConnector import LdapConnector
from configReader import Config
from logging_utils import configure_logging

kerberos_logger = logging.getLogger(__name__)

class Kerberos:
    def __init__(self, config: Config, ldap_connector: LdapConnector):
        self.config = config
        self.ldap = ldap_connector
        pass

    def getKerberoastableUsers(self):
        pass

    def getASREPRoastableUsers(self):
        pass

    def getDomainEncryptionPolicies(self):
        pass

    def getUnconstrainedDelegation(self):
        pass

    def getContrainedDelegation(self):
        pass
    def getResourceBasedConstrainedDelegation(self):
        pass
    
    pass